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

#include "iceberg/view/view_metadata.h"

#include <algorithm>
#include <format>

#include "iceberg/schema.h"
#include "iceberg/util/formatter.h"  // IWYU pragma: keep
#include "iceberg/util/macros.h"

namespace iceberg {

Result<std::shared_ptr<ViewVersion>> ViewMetadata::CurrentVersion() const {
  return VersionById(current_version_id);
}

Result<std::shared_ptr<ViewVersion>> ViewMetadata::VersionById(int32_t version_id) const {
  auto iter = std::ranges::find_if(versions, [version_id](const auto& version) {
    return version != nullptr && version->version_id == version_id;
  });
  if (iter == versions.end()) {
    return NotFound("View version {} is not found", version_id);
  }
  return *iter;
}

Result<std::shared_ptr<Schema>> ViewMetadata::CurrentSchema() const {
  ICEBERG_ASSIGN_OR_RAISE(auto version, CurrentVersion());
  return SchemaById(version->schema_id);
}

Result<std::shared_ptr<Schema>> ViewMetadata::SchemaById(int32_t schema_id) const {
  auto iter = std::ranges::find_if(schemas, [schema_id](const auto& schema) {
    return schema != nullptr && schema->schema_id() == schema_id;
  });
  if (iter == schemas.end()) {
    return NotFound("Schema {} is not found", schema_id);
  }
  return *iter;
}

namespace {

template <typename T>
bool SharedPtrListEquals(const std::vector<std::shared_ptr<T>>& lhs,
                         const std::vector<std::shared_ptr<T>>& rhs) {
  return std::ranges::equal(lhs, rhs, [](const auto& l, const auto& r) {
    if (!l || !r) {
      return !l && !r;
    }
    return *l == *r;
  });
}

}  // namespace

bool operator==(const ViewMetadata& lhs, const ViewMetadata& rhs) {
  return lhs.view_uuid == rhs.view_uuid && lhs.format_version == rhs.format_version &&
         lhs.location == rhs.location &&
         lhs.current_version_id == rhs.current_version_id &&
         SharedPtrListEquals(lhs.versions, rhs.versions) &&
         lhs.version_log == rhs.version_log &&
         SharedPtrListEquals(lhs.schemas, rhs.schemas) &&
         lhs.properties == rhs.properties;
}

std::string ToString(const ViewHistoryEntry& entry) {
  return std::format("ViewHistoryEntry[timestampMillis={},versionId={}]",
                     entry.timestamp_ms, entry.version_id);
}

}  // namespace iceberg
