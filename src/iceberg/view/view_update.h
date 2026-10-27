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

/// \file iceberg/view/view_update.h
/// Metadata update operations and update requirements for Iceberg views.

#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "iceberg/iceberg_export.h"
#include "iceberg/type_fwd.h"

namespace iceberg {

/// \brief Base class for view metadata update operations
///
/// Represents a change to view metadata. Each concrete subclass represents a specific
/// type of update operation as defined by the REST catalog API.
class ICEBERG_EXPORT ViewUpdate {
 public:
  enum class Kind : uint8_t {
    kAssignUUID,
    kUpgradeFormatVersion,
    kAddSchema,
    kSetLocation,
    kSetProperties,
    kRemoveProperties,
    kAddViewVersion,
    kSetCurrentViewVersion,
  };

  virtual ~ViewUpdate() = default;

  /// \brief Return the kind of this update.
  virtual Kind kind() const = 0;

  /// \brief Check equality with another ViewUpdate
  virtual bool Equals(const ViewUpdate& other) const = 0;

  /// \brief Create a deep copy of this update
  virtual std::unique_ptr<ViewUpdate> Clone() const = 0;

  friend bool operator==(const ViewUpdate& lhs, const ViewUpdate& rhs) {
    return lhs.Equals(rhs);
  }
};

/// \brief Base class for view update requirements
///
/// Represents a requirement that must be validated by the catalog before applying
/// metadata updates to a view.
class ICEBERG_EXPORT ViewRequirement {
 public:
  enum class Kind : uint8_t {
    kAssertViewUUID,
  };

  virtual ~ViewRequirement() = default;

  /// \brief Return the kind of requirement
  virtual Kind kind() const = 0;

  /// \brief Check equality with another ViewRequirement
  virtual bool Equals(const ViewRequirement& other) const = 0;

  /// \brief Create a deep copy of this requirement
  virtual std::unique_ptr<ViewRequirement> Clone() const = 0;

  friend bool operator==(const ViewRequirement& lhs, const ViewRequirement& rhs) {
    return lhs.Equals(rhs);
  }
};

namespace view {

/// \brief Represents an assignment of a UUID to the view
class ICEBERG_EXPORT AssignUUID : public ViewUpdate {
 public:
  explicit AssignUUID(std::string uuid) : uuid_(std::move(uuid)) {}

  const std::string& uuid() const { return uuid_; }

  Kind kind() const override { return Kind::kAssignUUID; }

  bool Equals(const ViewUpdate& other) const override;

  std::unique_ptr<ViewUpdate> Clone() const override;

 private:
  std::string uuid_;
};

/// \brief Represents an upgrade of the view format version
class ICEBERG_EXPORT UpgradeFormatVersion : public ViewUpdate {
 public:
  explicit UpgradeFormatVersion(int8_t format_version)
      : format_version_(format_version) {}

  int8_t format_version() const { return format_version_; }

  Kind kind() const override { return Kind::kUpgradeFormatVersion; }

  bool Equals(const ViewUpdate& other) const override;

  std::unique_ptr<ViewUpdate> Clone() const override;

 private:
  int8_t format_version_;
};

/// \brief Represents adding a new schema to the view
class ICEBERG_EXPORT AddSchema : public ViewUpdate {
 public:
  explicit AddSchema(std::shared_ptr<Schema> schema) : schema_(std::move(schema)) {}

  const std::shared_ptr<Schema>& schema() const { return schema_; }

  Kind kind() const override { return Kind::kAddSchema; }

  bool Equals(const ViewUpdate& other) const override;

  std::unique_ptr<ViewUpdate> Clone() const override;

 private:
  std::shared_ptr<Schema> schema_;
};

/// \brief Represents setting the view location
class ICEBERG_EXPORT SetLocation : public ViewUpdate {
 public:
  explicit SetLocation(std::string location) : location_(std::move(location)) {}

  const std::string& location() const { return location_; }

  Kind kind() const override { return Kind::kSetLocation; }

  bool Equals(const ViewUpdate& other) const override;

  std::unique_ptr<ViewUpdate> Clone() const override;

 private:
  std::string location_;
};

/// \brief Represents setting view properties
class ICEBERG_EXPORT SetProperties : public ViewUpdate {
 public:
  explicit SetProperties(std::unordered_map<std::string, std::string> updated)
      : updated_(std::move(updated)) {}

  const std::unordered_map<std::string, std::string>& updated() const { return updated_; }

  Kind kind() const override { return Kind::kSetProperties; }

  bool Equals(const ViewUpdate& other) const override;

  std::unique_ptr<ViewUpdate> Clone() const override;

 private:
  std::unordered_map<std::string, std::string> updated_;
};

/// \brief Represents removing view properties
class ICEBERG_EXPORT RemoveProperties : public ViewUpdate {
 public:
  explicit RemoveProperties(std::unordered_set<std::string> removed)
      : removed_(std::move(removed)) {}

  const std::unordered_set<std::string>& removed() const { return removed_; }

  Kind kind() const override { return Kind::kRemoveProperties; }

  bool Equals(const ViewUpdate& other) const override;

  std::unique_ptr<ViewUpdate> Clone() const override;

 private:
  std::unordered_set<std::string> removed_;
};

/// \brief Represents adding a new version to the view
class ICEBERG_EXPORT AddViewVersion : public ViewUpdate {
 public:
  explicit AddViewVersion(std::shared_ptr<ViewVersion> view_version)
      : view_version_(std::move(view_version)) {}

  const std::shared_ptr<ViewVersion>& view_version() const { return view_version_; }

  Kind kind() const override { return Kind::kAddViewVersion; }

  bool Equals(const ViewUpdate& other) const override;

  std::unique_ptr<ViewUpdate> Clone() const override;

 private:
  std::shared_ptr<ViewVersion> view_version_;
};

/// \brief Represents setting the current version of the view
class ICEBERG_EXPORT SetCurrentViewVersion : public ViewUpdate {
 public:
  /// The version id of the last added version
  static constexpr int32_t kLastAdded = -1;

  explicit SetCurrentViewVersion(int32_t view_version_id)
      : view_version_id_(view_version_id) {}

  /// \brief The version id to set as current, or kLastAdded for the last added version
  int32_t view_version_id() const { return view_version_id_; }

  Kind kind() const override { return Kind::kSetCurrentViewVersion; }

  bool Equals(const ViewUpdate& other) const override;

  std::unique_ptr<ViewUpdate> Clone() const override;

 private:
  int32_t view_version_id_;
};

/// \brief Requirement that the view UUID matches the expected value
class ICEBERG_EXPORT AssertViewUUID : public ViewRequirement {
 public:
  explicit AssertViewUUID(std::string uuid) : uuid_(std::move(uuid)) {}

  const std::string& uuid() const { return uuid_; }

  Kind kind() const override { return Kind::kAssertViewUUID; }

  bool Equals(const ViewRequirement& other) const override;

  std::unique_ptr<ViewRequirement> Clone() const override;

 private:
  std::string uuid_;
};

}  // namespace view

}  // namespace iceberg
