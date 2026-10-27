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

#pragma once

/// \file iceberg/view/view_metadata.h
/// View metadata for Iceberg views.

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "iceberg/iceberg_export.h"
#include "iceberg/result.h"
#include "iceberg/table_identifier.h"
#include "iceberg/type_fwd.h"
#include "iceberg/util/timepoint.h"

namespace iceberg {

/// \brief One representation of a view definition.
///
/// Only the "sql" type is defined by the spec and carries \c sql and \c dialect. A
/// representation of any other type is kept with its \c type only so that metadata
/// written by other engines round-trips without losing entries.
struct ICEBERG_EXPORT ViewRepresentation {
  static constexpr std::string_view kSqlType = "sql";

  /// Representation type, "sql" for a SQL SELECT statement
  std::string type;
  /// The SQL SELECT statement; set when type is "sql"
  std::string sql;
  /// The dialect of the SQL statement (e.g. "spark"); set when type is "sql"
  std::string dialect;

  bool operator==(const ViewRepresentation&) const = default;
};

/// \brief Represents a version log entry
struct ICEBERG_EXPORT ViewHistoryEntry {
  /// Timestamp when the view's current-version-id was set to version_id
  TimePointMs timestamp_ms;
  /// ID that current-version-id was set to
  int32_t version_id;

  bool operator==(const ViewHistoryEntry&) const = default;
};

/// \brief The state of a view at some point in time
struct ICEBERG_EXPORT ViewVersion {
  /// ID for the version
  int32_t version_id;
  /// ID of the schema for the view version
  int32_t schema_id;
  /// Timestamp when the version was created
  TimePointMs timestamp_ms;
  /// A string to string map of summary metadata about the version
  std::unordered_map<std::string, std::string> summary;
  /// A list of representations for the view definition
  std::vector<ViewRepresentation> representations;
  /// Catalog name to use when a reference in the SELECT does not contain a catalog
  std::optional<std::string> default_catalog;
  /// Namespace to use when a reference in the SELECT is a single identifier
  Namespace default_namespace;
  /// Identifier of the storage table; set only for a materialized view
  std::optional<TableIdentifier> storage_table;

  bool operator==(const ViewVersion&) const = default;
};

/// \brief Represents the metadata for an Iceberg view
struct ICEBERG_EXPORT ViewMetadata {
  static constexpr int8_t kDefaultViewFormatVersion = 1;
  static constexpr int8_t kSupportedViewFormatVersion = 1;

  /// A UUID that identifies the view
  std::string view_uuid;
  /// An integer version number for the view format
  int8_t format_version;
  /// The view's base location
  std::string location;
  /// ID of the current version of the view
  int32_t current_version_id;
  /// A list of known versions of the view
  std::vector<std::shared_ptr<ViewVersion>> versions;
  /// A list of timestamp and version-id pairs for every change to current_version_id
  std::vector<ViewHistoryEntry> version_log;
  /// A list of known schemas
  std::vector<std::shared_ptr<iceberg::Schema>> schemas;
  /// A string to string map of view properties
  std::unordered_map<std::string, std::string> properties;

  /// \brief Get the current version, return NotFoundError if not found
  /// \note The returned version is guaranteed to be not null
  Result<std::shared_ptr<ViewVersion>> CurrentVersion() const;
  /// \brief Get the version by ID, return NotFoundError if not found
  /// \note The returned version is guaranteed to be not null
  Result<std::shared_ptr<ViewVersion>> VersionById(int32_t version_id) const;
  /// \brief Get the schema of the current version, return NotFoundError if not found
  /// \note The returned schema is guaranteed to be not null
  Result<std::shared_ptr<iceberg::Schema>> CurrentSchema() const;
  /// \brief Get the schema by ID, return NotFoundError if not found
  /// \note The returned schema is guaranteed to be not null
  Result<std::shared_ptr<iceberg::Schema>> SchemaById(int32_t schema_id) const;

  ICEBERG_EXPORT friend bool operator==(const ViewMetadata& lhs, const ViewMetadata& rhs);
};

/// \brief Returns a string representation of a ViewHistoryEntry
ICEBERG_EXPORT std::string ToString(const ViewHistoryEntry& entry);

}  // namespace iceberg
