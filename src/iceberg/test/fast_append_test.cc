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

#include "iceberg/update/fast_append.h"

#include <format>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "iceberg/avro/avro_register.h"
#include "iceberg/expression/literal.h"
#include "iceberg/manifest/manifest_reader.h"
#include "iceberg/partition_spec.h"
#include "iceberg/schema.h"
#include "iceberg/table_metadata.h"
#include "iceberg/test/matchers.h"
#include "iceberg/test/test_resource.h"
#include "iceberg/test/update_test_base.h"
#include "iceberg/util/uuid.h"

namespace iceberg {

class FastAppendTest : public UpdateTestBase {
 protected:
  static void SetUpTestSuite() { avro::RegisterAll(); }

  std::string MetadataResource() const override {
    return "TableMetadataV2ValidMinimal.json";
  }

  void SetUp() override {
    UpdateTestBase::SetUp();

    // Get partition spec and schema from the base table
    ICEBERG_UNWRAP_OR_FAIL(spec_, table_->spec());
    ICEBERG_UNWRAP_OR_FAIL(schema_, table_->schema());

    // Create test data files
    file_a_ =
        CreateDataFile("/data/file_a.parquet", /*size=*/100, /*partition_value=*/1024);
    file_b_ =
        CreateDataFile("/data/file_b.parquet", /*size=*/200, /*partition_value=*/2048);
  }

  std::shared_ptr<DataFile> CreateDataFile(const std::string& path, int64_t record_count,
                                           int64_t size, int64_t partition_value = 0) {
    auto data_file = std::make_shared<DataFile>();
    data_file->content = DataFile::Content::kData;
    data_file->file_path = table_location_ + path;
    data_file->file_format = FileFormatType::kParquet;
    // The base table has partition spec with identity(x), so we need 1 partition value
    data_file->partition =
        PartitionValues(std::vector<Literal>{Literal::Long(partition_value)});
    data_file->file_size_in_bytes = size;
    data_file->record_count = record_count;
    data_file->partition_spec_id = spec_->spec_id();
    return data_file;
  }

  std::shared_ptr<PartitionSpec> spec_;
  std::shared_ptr<Schema> schema_;
  std::shared_ptr<DataFile> file_a_;
  std::shared_ptr<DataFile> file_b_;
};

TEST_F(FastAppendTest, AppendDataFile) {
  std::shared_ptr<FastAppend> fast_append;
  ICEBERG_UNWRAP_OR_FAIL(fast_append, table_->NewFastAppend());
  fast_append->AppendFile(file_a_);

  EXPECT_THAT(fast_append->Commit(), IsOk());

  EXPECT_THAT(table_->Refresh(), IsOk());
  ICEBERG_UNWRAP_OR_FAIL(auto snapshot, table_->current_snapshot());
  EXPECT_EQ(snapshot->summary.at("added-data-files"), "1");
  EXPECT_EQ(snapshot->summary.at("added-records"), "100");
  EXPECT_EQ(snapshot->summary.at("added-files-size"), "1024");
}

TEST_F(FastAppendTest, AppendMultipleDataFiles) {
  std::shared_ptr<FastAppend> fast_append;
  ICEBERG_UNWRAP_OR_FAIL(fast_append, table_->NewFastAppend());
  fast_append->AppendFile(file_a_);
  fast_append->AppendFile(file_b_);

  EXPECT_THAT(fast_append->Commit(), IsOk());

  EXPECT_THAT(table_->Refresh(), IsOk());
  ICEBERG_UNWRAP_OR_FAIL(auto snapshot, table_->current_snapshot());
  EXPECT_EQ(snapshot->summary.at("added-data-files"), "2");
  EXPECT_EQ(snapshot->summary.at("added-records"), "300");
  EXPECT_EQ(snapshot->summary.at("added-files-size"), "3072");
}

TEST_F(FastAppendTest, AppendManyFiles) {
  std::shared_ptr<FastAppend> fast_append;
  ICEBERG_UNWRAP_OR_FAIL(fast_append, table_->NewFastAppend());

  int64_t total_records = 0;
  int64_t total_size = 0;
  constexpr int kFileCount = 10;
  for (int index = 0; index < kFileCount; ++index) {
    auto data_file = CreateDataFile(std::format("/data/file_{}.parquet", index),
                                    /*record_count=*/10 + index,
                                    /*size=*/100 + index * 10,
                                    /*partition_value=*/index % 2);
    total_records += data_file->record_count;
    total_size += data_file->file_size_in_bytes;
    fast_append->AppendFile(std::move(data_file));
  }

  EXPECT_THAT(fast_append->Commit(), IsOk());

  EXPECT_THAT(table_->Refresh(), IsOk());
  ICEBERG_UNWRAP_OR_FAIL(auto snapshot, table_->current_snapshot());
  EXPECT_EQ(snapshot->summary.at("added-data-files"), std::to_string(kFileCount));
  EXPECT_EQ(snapshot->summary.at("added-records"), std::to_string(total_records));
  EXPECT_EQ(snapshot->summary.at("added-files-size"), std::to_string(total_size));
}

TEST_F(FastAppendTest, EmptyTableAppendUpdatesSequenceNumbers) {
  EXPECT_THAT(table_->current_snapshot(), HasErrorMessage("No current snapshot"));
  const int64_t base_sequence_number = table_->metadata()->last_sequence_number;

  std::shared_ptr<FastAppend> fast_append;
  ICEBERG_UNWRAP_OR_FAIL(fast_append, table_->NewFastAppend());
  fast_append->AppendFile(file_a_);

  EXPECT_THAT(fast_append->Commit(), IsOk());

  EXPECT_THAT(table_->Refresh(), IsOk());
  ICEBERG_UNWRAP_OR_FAIL(auto snapshot, table_->current_snapshot());
  EXPECT_EQ(snapshot->sequence_number, base_sequence_number + 1);
  EXPECT_EQ(table_->metadata()->last_sequence_number, base_sequence_number + 1);
}

TEST_F(FastAppendTest, AppendNullFile) {
  std::shared_ptr<FastAppend> fast_append;
  ICEBERG_UNWRAP_OR_FAIL(fast_append, table_->NewFastAppend());
  fast_append->AppendFile(nullptr);

  auto result = fast_append->Commit();
  EXPECT_FALSE(result.has_value());
  EXPECT_THAT(result, HasErrorMessage("Invalid data file: null"));
  EXPECT_THAT(table_->current_snapshot(), HasErrorMessage("No current snapshot"));
}

TEST_F(FastAppendTest, AppendDuplicateFile) {
  std::shared_ptr<FastAppend> fast_append;
  ICEBERG_UNWRAP_OR_FAIL(fast_append, table_->NewFastAppend());
  fast_append->AppendFile(file_a_);
  fast_append->AppendFile(file_a_);  // Add same file twice

  EXPECT_THAT(fast_append->Commit(), IsOk());

  EXPECT_THAT(table_->Refresh(), IsOk());
  ICEBERG_UNWRAP_OR_FAIL(auto snapshot, table_->current_snapshot());
  // Should only count the file once
  EXPECT_EQ(snapshot->summary.at("added-data-files"), "1");
  EXPECT_EQ(snapshot->summary.at("added-records"), "100");
}

TEST_F(FastAppendTest, SetSnapshotProperty) {
  std::shared_ptr<FastAppend> fast_append;
  ICEBERG_UNWRAP_OR_FAIL(fast_append, table_->NewFastAppend());
  fast_append->Set("custom-property", "custom-value");
  fast_append->AppendFile(file_a_);

  EXPECT_THAT(fast_append->Commit(), IsOk());

  EXPECT_THAT(table_->Refresh(), IsOk());
  ICEBERG_UNWRAP_OR_FAIL(auto snapshot, table_->current_snapshot());
  EXPECT_EQ(snapshot->summary.at("custom-property"), "custom-value");
}

TEST_F(FastAppendTest, AppendDataFileWithMetrics) {
  // Schema has fields: x(id=1, long), y(id=2, long), z(id=3, long)
  // Create a DataFile with full metrics populated
  auto data_file = std::make_shared<DataFile>();
  data_file->content = DataFile::Content::kData;
  data_file->file_path = table_location_ + "/data/file_with_metrics.parquet";
  data_file->file_format = FileFormatType::kParquet;
  data_file->partition = PartitionValues(std::vector<Literal>{Literal::Long(42)});
  data_file->file_size_in_bytes = 2048;
  data_file->record_count = 500;
  data_file->partition_spec_id = spec_->spec_id();

  // Populate metrics using the table's column field IDs
  data_file->column_sizes = {{1, 512}, {2, 768}, {3, 256}};
  data_file->value_counts = {{1, 500}, {2, 500}, {3, 500}};
  data_file->null_value_counts = {{1, 0}, {2, 5}, {3, 10}};
  data_file->nan_value_counts = {{1, 0}};

  // Serialize bounds as binary (Long type = int64)
  ICEBERG_UNWRAP_OR_FAIL(auto lower1, Literal::Long(100).Serialize());
  ICEBERG_UNWRAP_OR_FAIL(auto upper1, Literal::Long(999).Serialize());
  ICEBERG_UNWRAP_OR_FAIL(auto lower2, Literal::Long(200).Serialize());
  ICEBERG_UNWRAP_OR_FAIL(auto upper2, Literal::Long(888).Serialize());
  data_file->lower_bounds = {{1, lower1}, {2, lower2}};
  data_file->upper_bounds = {{1, upper1}, {2, upper2}};

  // Commit via FastAppend
  std::shared_ptr<FastAppend> fast_append;
  ICEBERG_UNWRAP_OR_FAIL(fast_append, table_->NewFastAppend());
  fast_append->AppendFile(data_file);
  EXPECT_THAT(fast_append->Commit(), IsOk());

  // Refresh and get the snapshot
  EXPECT_THAT(table_->Refresh(), IsOk());
  ICEBERG_UNWRAP_OR_FAIL(auto snapshot, table_->current_snapshot());

  // Read the manifest list to get manifest files
  ICEBERG_UNWRAP_OR_FAIL(auto list_reader,
                         ManifestListReader::Make(snapshot->manifest_list, file_io_));
  ICEBERG_UNWRAP_OR_FAIL(auto manifest_files, list_reader->Files());
  ASSERT_FALSE(manifest_files.empty());

  // Read manifest entries from the first data manifest
  const auto& manifest = manifest_files[0];
  ICEBERG_UNWRAP_OR_FAIL(auto reader,
                         ManifestReader::Make(manifest, file_io_, schema_, spec_));
  ICEBERG_UNWRAP_OR_FAIL(auto entries, reader->Entries());
  ASSERT_EQ(entries.size(), 1);

  // Verify the DataFile metrics survived the round-trip
  const auto& read_file = *entries[0].data_file;
  EXPECT_EQ(read_file.file_path, data_file->file_path);
  EXPECT_EQ(read_file.record_count, 500);
  EXPECT_EQ(read_file.file_size_in_bytes, 2048);

  // Verify column_sizes
  EXPECT_EQ(read_file.column_sizes, data_file->column_sizes);

  // Verify value_counts
  EXPECT_EQ(read_file.value_counts, data_file->value_counts);

  // Verify null_value_counts
  EXPECT_EQ(read_file.null_value_counts, data_file->null_value_counts);

  // Verify nan_value_counts
  EXPECT_EQ(read_file.nan_value_counts, data_file->nan_value_counts);

  // Verify lower_bounds
  EXPECT_EQ(read_file.lower_bounds, data_file->lower_bounds);

  // Verify upper_bounds
  EXPECT_EQ(read_file.upper_bounds, data_file->upper_bounds);
}

}  // namespace iceberg
