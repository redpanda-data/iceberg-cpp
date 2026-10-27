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

#include "iceberg/view/view_update.h"

#include "iceberg/schema.h"
#include "iceberg/util/checked_cast.h"
#include "iceberg/view/view_metadata.h"

namespace iceberg::view {

namespace {

template <typename T>
bool SharedPtrEquals(const std::shared_ptr<T>& lhs, const std::shared_ptr<T>& rhs) {
  if (!lhs || !rhs) {
    return !lhs && !rhs;
  }
  return *lhs == *rhs;
}

}  // namespace

bool AssignUUID::Equals(const ViewUpdate& other) const {
  return other.kind() == Kind::kAssignUUID &&
         uuid_ == internal::checked_cast<const AssignUUID&>(other).uuid_;
}

std::unique_ptr<ViewUpdate> AssignUUID::Clone() const {
  return std::make_unique<AssignUUID>(uuid_);
}

bool UpgradeFormatVersion::Equals(const ViewUpdate& other) const {
  return other.kind() == Kind::kUpgradeFormatVersion &&
         format_version_ ==
             internal::checked_cast<const UpgradeFormatVersion&>(other).format_version_;
}

std::unique_ptr<ViewUpdate> UpgradeFormatVersion::Clone() const {
  return std::make_unique<UpgradeFormatVersion>(format_version_);
}

bool AddSchema::Equals(const ViewUpdate& other) const {
  return other.kind() == Kind::kAddSchema &&
         SharedPtrEquals(schema_,
                         internal::checked_cast<const AddSchema&>(other).schema_);
}

std::unique_ptr<ViewUpdate> AddSchema::Clone() const {
  return std::make_unique<AddSchema>(schema_);
}

bool SetLocation::Equals(const ViewUpdate& other) const {
  return other.kind() == Kind::kSetLocation &&
         location_ == internal::checked_cast<const SetLocation&>(other).location_;
}

std::unique_ptr<ViewUpdate> SetLocation::Clone() const {
  return std::make_unique<SetLocation>(location_);
}

bool SetProperties::Equals(const ViewUpdate& other) const {
  return other.kind() == Kind::kSetProperties &&
         updated_ == internal::checked_cast<const SetProperties&>(other).updated_;
}

std::unique_ptr<ViewUpdate> SetProperties::Clone() const {
  return std::make_unique<SetProperties>(updated_);
}

bool RemoveProperties::Equals(const ViewUpdate& other) const {
  return other.kind() == Kind::kRemoveProperties &&
         removed_ == internal::checked_cast<const RemoveProperties&>(other).removed_;
}

std::unique_ptr<ViewUpdate> RemoveProperties::Clone() const {
  return std::make_unique<RemoveProperties>(removed_);
}

bool AddViewVersion::Equals(const ViewUpdate& other) const {
  return other.kind() == Kind::kAddViewVersion &&
         SharedPtrEquals(
             view_version_,
             internal::checked_cast<const AddViewVersion&>(other).view_version_);
}

std::unique_ptr<ViewUpdate> AddViewVersion::Clone() const {
  return std::make_unique<AddViewVersion>(view_version_);
}

bool SetCurrentViewVersion::Equals(const ViewUpdate& other) const {
  return other.kind() == Kind::kSetCurrentViewVersion &&
         view_version_id_ ==
             internal::checked_cast<const SetCurrentViewVersion&>(other).view_version_id_;
}

std::unique_ptr<ViewUpdate> SetCurrentViewVersion::Clone() const {
  return std::make_unique<SetCurrentViewVersion>(view_version_id_);
}

bool AssertViewUUID::Equals(const ViewRequirement& other) const {
  return other.kind() == Kind::kAssertViewUUID &&
         uuid_ == internal::checked_cast<const AssertViewUUID&>(other).uuid_;
}

std::unique_ptr<ViewRequirement> AssertViewUUID::Clone() const {
  return std::make_unique<AssertViewUUID>(uuid_);
}

}  // namespace iceberg::view
