/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

#include "iceberg/parquet/parquet_writer.h"

#include <memory>

#include <arrow/c/bridge.h>
#include <arrow/record_batch.h>
#include <arrow/util/key_value_metadata.h>
#include <parquet/arrow/schema.h>
#include <parquet/arrow/writer.h>
#include <parquet/file_writer.h>
#include <parquet/metadata.h>
#include <parquet/properties.h>
#include <parquet/schema.h>
#include <parquet/statistics.h>

#include "iceberg/arrow/arrow_fs_file_io_internal.h"
#include "iceberg/arrow/arrow_status_internal.h"
#include "iceberg/expression/literal.h"
#include "iceberg/metrics.h"
#include "iceberg/schema.h"
#include "iceberg/schema_field.h"
#include "iceberg/schema_internal.h"
#include "iceberg/type.h"
#include "iceberg/util/checked_cast.h"
#include "iceberg/util/macros.h"

namespace iceberg::parquet {

namespace {

Result<std::shared_ptr<::arrow::io::OutputStream>> OpenOutputStream(
    const WriterOptions& options) {
  auto io = internal::checked_pointer_cast<arrow::ArrowFileSystemFileIO>(options.io);
  ICEBERG_ARROW_ASSIGN_OR_RETURN(auto output, io->fs()->OpenOutputStream(options.path));
  return output;
}

Result<::arrow::Compression::type> ParseCompression(const WriterProperties& properties) {
  const auto& compression_name = properties.Get(WriterProperties::kParquetCompression);
  if (compression_name == "uncompressed") {
    return ::arrow::Compression::UNCOMPRESSED;
  } else if (compression_name == "snappy") {
    return ::arrow::Compression::SNAPPY;
  } else if (compression_name == "gzip") {
    return ::arrow::Compression::GZIP;
  } else if (compression_name == "brotli") {
    return ::arrow::Compression::BROTLI;
  } else if (compression_name == "lz4") {
    return ::arrow::Compression::LZ4;
  } else if (compression_name == "zstd") {
    return ::arrow::Compression::ZSTD;
  } else {
    return InvalidArgument("Unsupported Parquet compression codec: {}", compression_name);
  }
}

Result<std::optional<int32_t>> ParseCodecLevel(const WriterProperties& properties) {
  auto level_str = properties.Get(WriterProperties::kParquetCompressionLevel);
  if (level_str.empty()) {
    return std::nullopt;
  }
  ICEBERG_ASSIGN_OR_RAISE(auto level, StringUtils::ParseNumber<int32_t>(level_str));
  return level;
}

}  // namespace

class ParquetWriter::Impl {
 public:
  Status Open(const WriterOptions& options) {
    ICEBERG_ASSIGN_OR_RAISE(auto compression, ParseCompression(options.properties));
    ICEBERG_ASSIGN_OR_RAISE(auto compression_level, ParseCodecLevel(options.properties));

    auto properties_builder = ::parquet::WriterProperties::Builder();
    properties_builder.compression(compression);
    if (compression_level.has_value()) {
      properties_builder.compression_level(compression_level.value());
    }
    auto writer_properties = properties_builder.memory_pool(pool_)->build();
    auto arrow_writer_properties = ::parquet::default_arrow_writer_properties();

    ArrowSchema c_schema;
    ICEBERG_RETURN_UNEXPECTED(ToArrowSchema(*options.schema, &c_schema));
    ICEBERG_ARROW_ASSIGN_OR_RETURN(arrow_schema_, ::arrow::ImportSchema(&c_schema));

    std::shared_ptr<::parquet::SchemaDescriptor> schema_descriptor;
    ICEBERG_ARROW_RETURN_NOT_OK(
        ::parquet::arrow::ToParquetSchema(arrow_schema_.get(), *writer_properties,
                                          *arrow_writer_properties, &schema_descriptor));
    auto schema_node = std::static_pointer_cast<::parquet::schema::GroupNode>(
        schema_descriptor->schema_root());

    ICEBERG_ASSIGN_OR_RAISE(output_stream_, OpenOutputStream(options));
    auto file_writer = ::parquet::ParquetFileWriter::Open(
        output_stream_, std::move(schema_node), std::move(writer_properties),
        std::make_shared<::arrow::KeyValueMetadata>(options.metadata));
    ICEBERG_ARROW_RETURN_NOT_OK(
        ::parquet::arrow::FileWriter::Make(pool_, std::move(file_writer), arrow_schema_,
                                           std::move(arrow_writer_properties), &writer_));

    iceberg_schema_ = options.schema;

    return {};
  }

  Status Write(ArrowArray* array) {
    ICEBERG_ARROW_ASSIGN_OR_RETURN(auto batch,
                                   ::arrow::ImportRecordBatch(array, arrow_schema_));

    ICEBERG_ARROW_RETURN_NOT_OK(writer_->WriteRecordBatch(*batch));

    return {};
  }

  // Close the writer and release resources
  Status Close() {
    if (writer_ == nullptr) {
      return {};  // Already closed
    }

    ICEBERG_ARROW_RETURN_NOT_OK(writer_->Close());
    auto& metadata = writer_->metadata();
    split_offsets_.reserve(metadata->num_row_groups());
    for (int i = 0; i < metadata->num_row_groups(); ++i) {
      split_offsets_.push_back(metadata->RowGroup(i)->file_offset());
    }
    PopulateMetrics(*metadata);
    writer_.reset();

    ICEBERG_ARROW_ASSIGN_OR_RETURN(total_bytes_, output_stream_->Tell());
    ICEBERG_ARROW_RETURN_NOT_OK(output_stream_->Close());
    return {};
  }

  bool Closed() const { return writer_ == nullptr; }

  Result<int64_t> length() {
    if (Closed()) {
      return total_bytes_;
    }
    // Return current flushed length when writer is still open.
    // It would be good if we could get the number of buffered bytes
    // from the internal RowGroupWriter.
    ICEBERG_ARROW_ASSIGN_OR_RETURN(auto current_pos, output_stream_->Tell());
    return current_pos;
  }

  std::vector<int64_t> split_offsets() const { return split_offsets_; }

  const Metrics& metrics() const { return metrics_; }

 private:
  // Populate the Metrics struct from the Parquet file's FileMetaData.
  // Column chunk stats are aggregated across row groups, and Parquet physical
  // min/max bytes are decoded into Iceberg Literals via the single-value
  // binary serialization format (which matches Parquet's physical encoding
  // for primitive types).
  void PopulateMetrics(const ::parquet::FileMetaData& metadata) {
    metrics_ = {};
    metrics_.row_count = metadata.num_rows();

    if (iceberg_schema_ == nullptr) {
      return;
    }

    const int num_columns = metadata.num_columns();
    std::vector<int32_t> field_ids(num_columns, -1);
    std::vector<std::shared_ptr<PrimitiveType>> field_types(num_columns);
    for (int c = 0; c < num_columns; ++c) {
      const auto* col_desc = metadata.schema()->Column(c);
      auto node = col_desc->schema_node();
      if (!node || node->field_id() < 0) continue;
      const int32_t fid = node->field_id();
      auto field_result = iceberg_schema_->FindFieldById(fid);
      if (!field_result.has_value() || !field_result->has_value()) continue;
      const auto& type = field_result->value().get().type();
      if (!type || !type->is_primitive()) continue;
      field_ids[c] = fid;
      field_types[c] = std::static_pointer_cast<PrimitiveType>(type);
    }

    // Holders for running min/max bytes per field_id.
    std::unordered_map<int32_t, std::string> min_bounds;
    std::unordered_map<int32_t, std::string> max_bounds;

    for (int rg = 0; rg < metadata.num_row_groups(); ++rg) {
      const auto row_group = metadata.RowGroup(rg);
      for (int c = 0; c < num_columns; ++c) {
        const int32_t fid = field_ids[c];
        if (fid < 0) continue;
        const auto col_chunk = row_group->ColumnChunk(c);
        metrics_.column_sizes[fid] += col_chunk->total_compressed_size();
        metrics_.value_counts[fid] += col_chunk->num_values();

        if (!col_chunk->is_stats_set()) continue;
        auto stats = col_chunk->statistics();
        if (!stats) continue;
        if (stats->HasNullCount()) {
          metrics_.null_value_counts[fid] += stats->null_count();
        }
        if (stats->HasMinMax()) {
          auto min_bytes = stats->EncodeMin();
          auto max_bytes = stats->EncodeMax();
          auto& cur_min = min_bounds[fid];
          auto& cur_max = max_bounds[fid];
          if (cur_min.empty() || min_bytes < cur_min) {
            cur_min = std::move(min_bytes);
          }
          if (cur_max.empty() || max_bytes > cur_max) {
            cur_max = std::move(max_bytes);
          }
        }
      }
    }

    for (auto& [fid, bytes] : min_bounds) {
      const auto& type = field_types[FindColumnIndex(field_ids, fid)];
      auto lit = Literal::Deserialize(
          std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(bytes.data()),
                                   bytes.size()),
          type);
      if (lit.has_value()) {
        metrics_.lower_bounds.emplace(fid, std::move(*lit));
      }
    }
    for (auto& [fid, bytes] : max_bounds) {
      const auto& type = field_types[FindColumnIndex(field_ids, fid)];
      auto lit = Literal::Deserialize(
          std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(bytes.data()),
                                   bytes.size()),
          type);
      if (lit.has_value()) {
        metrics_.upper_bounds.emplace(fid, std::move(*lit));
      }
    }
  }

  static int FindColumnIndex(const std::vector<int32_t>& field_ids, int32_t fid) {
    for (size_t i = 0; i < field_ids.size(); ++i) {
      if (field_ids[i] == fid) return static_cast<int>(i);
    }
    return -1;
  }

  // TODO(gangwu): make memory pool configurable
  ::arrow::MemoryPool* pool_ = ::arrow::default_memory_pool();
  // Schema to write from the Parquet file.
  std::shared_ptr<::arrow::Schema> arrow_schema_;
  // Iceberg schema, retained for field_id/type lookup when populating metrics.
  std::shared_ptr<Schema> iceberg_schema_;
  // The output stream to write Parquet file.
  std::shared_ptr<::arrow::io::OutputStream> output_stream_;
  // Parquet file writer to write ArrowArray.
  std::unique_ptr<::parquet::arrow::FileWriter> writer_;
  // Total length of the written Parquet file.
  int64_t total_bytes_{0};
  // Row group start offsets in the Parquet file.
  std::vector<int64_t> split_offsets_;
  // Computed file metrics, filled in Close().
  Metrics metrics_;
};

ParquetWriter::~ParquetWriter() = default;

Status ParquetWriter::Open(const WriterOptions& options) {
  impl_ = std::make_unique<Impl>();
  return impl_->Open(options);
}

Status ParquetWriter::Write(ArrowArray* array) { return impl_->Write(array); }

Status ParquetWriter::Close() { return impl_->Close(); }

Result<Metrics> ParquetWriter::metrics() {
  if (!impl_->Closed()) {
    return Invalid("ParquetWriter is not closed");
  }
  return impl_->metrics();
}

Result<int64_t> ParquetWriter::length() { return impl_->length(); }

std::vector<int64_t> ParquetWriter::split_offsets() {
  if (!impl_->Closed()) {
    return {};
  }
  return impl_->split_offsets();
}

void RegisterWriter() {
  static WriterFactoryRegistry parquet_writer_register(
      FileFormatType::kParquet, []() -> Result<std::unique_ptr<Writer>> {
        return std::make_unique<ParquetWriter>();
      });
}

}  // namespace iceberg::parquet
