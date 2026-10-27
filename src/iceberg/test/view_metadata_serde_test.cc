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

#include <filesystem>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include "iceberg/json_serde_internal.h"
#include "iceberg/schema.h"
#include "iceberg/schema_field.h"
#include "iceberg/table_identifier.h"
#include "iceberg/test/matchers.h"
#include "iceberg/test/test_resource.h"
#include "iceberg/type.h"
#include "iceberg/view/view_metadata.h"
#include "iceberg/view/view_update.h"

namespace iceberg {

namespace {

nlohmann::json ReadJsonResource(const std::string& file_name) {
  std::ifstream file(GetResourcePath(file_name));
  std::stringstream buffer;
  buffer << file.rdbuf();
  return nlohmann::json::parse(buffer.str());
}

std::shared_ptr<ViewVersion> MakeVersion(std::optional<TableIdentifier> storage_table) {
  return std::make_shared<ViewVersion>(ViewVersion{
      .version_id = 1,
      .schema_id = 1,
      .timestamp_ms = TimePointMsFromUnixMs(1573518431292),
      .summary = {{"engine-name", "Spark"}},
      .representations = {{.type = "sql", .sql = "SELECT 1", .dialect = "spark"}},
      .default_catalog = "prod",
      .default_namespace = {.levels = {"default"}},
      .storage_table = std::move(storage_table),
  });
}

}  // namespace

class ViewMetadataSerdeTest : public ::testing::TestWithParam<std::string> {};

TEST_P(ViewMetadataSerdeTest, RoundTripsSpecExample) {
  auto json = ReadJsonResource(GetParam());
  auto metadata = ViewMetadataFromJson(json);
  ASSERT_THAT(metadata, IsOk());

  auto serialized = ToJson(*metadata.value());
  ASSERT_THAT(serialized, IsOk());
  EXPECT_EQ(serialized.value(), json);

  auto reparsed = ViewMetadataFromJson(serialized.value());
  ASSERT_THAT(reparsed, IsOk());
  EXPECT_EQ(*reparsed.value(), *metadata.value());
}

TEST_P(ViewMetadataSerdeTest, ResolvesCurrentVersionAndSchema) {
  auto metadata = ViewMetadataFromJson(ReadJsonResource(GetParam()));
  ASSERT_THAT(metadata, IsOk());

  auto version = metadata.value()->CurrentVersion();
  ASSERT_THAT(version, IsOk());
  EXPECT_EQ(version.value()->version_id, metadata.value()->current_version_id);
  EXPECT_EQ(version.value()->default_catalog, "prod");
  EXPECT_EQ(version.value()->default_namespace, (Namespace{.levels = {"default"}}));
  ASSERT_EQ(version.value()->representations.size(), 1);
  EXPECT_EQ(version.value()->representations[0].type, "sql");
  EXPECT_EQ(version.value()->representations[0].dialect, "spark");

  auto schema = metadata.value()->CurrentSchema();
  ASSERT_THAT(schema, IsOk());
  const Schema expected({SchemaField(1, "event_count", int32(), true, "Count of events"),
                         SchemaField(2, "event_date", date(), true)},
                        1);
  EXPECT_EQ(*schema.value(), expected);
}

INSTANTIATE_TEST_SUITE_P(SpecExamples, ViewMetadataSerdeTest,
                         ::testing::Values("ViewMetadataV1Valid.json",
                                           "ViewMetadataV1TwoVersions.json",
                                           "ViewMetadataV1MaterializedView.json"));

TEST(ViewMetadataSerde, KeepsStorageTableOfMaterializedView) {
  auto json = ReadJsonResource("ViewMetadataV1MaterializedView.json");
  auto metadata = ViewMetadataFromJson(json);
  ASSERT_THAT(metadata, IsOk());

  const TableIdentifier expected{.ns = {.levels = {"default"}},
                                 .name = "event_agg_mv__storage"};
  auto version = metadata.value()->CurrentVersion();
  ASSERT_THAT(version, IsOk());
  EXPECT_EQ(version.value()->storage_table, expected);

  auto serialized = ToJson(*metadata.value());
  ASSERT_THAT(serialized, IsOk());
  EXPECT_EQ(serialized.value()["versions"][0]["storage-table"],
            json["versions"][0]["storage-table"]);

  auto reparsed = ViewMetadataFromJson(serialized.value());
  ASSERT_THAT(reparsed, IsOk());
  auto reparsed_version = reparsed.value()->CurrentVersion();
  ASSERT_THAT(reparsed_version, IsOk());
  EXPECT_EQ(reparsed_version.value()->storage_table, expected);
}

TEST(ViewMetadataSerde, OmitsStorageTableOfPlainView) {
  auto metadata = ViewMetadataFromJson(ReadJsonResource("ViewMetadataV1Valid.json"));
  ASSERT_THAT(metadata, IsOk());
  auto version = metadata.value()->CurrentVersion();
  ASSERT_THAT(version, IsOk());
  EXPECT_EQ(version.value()->storage_table, std::nullopt);

  auto serialized = ToJson(*metadata.value());
  ASSERT_THAT(serialized, IsOk());
  EXPECT_FALSE(serialized.value()["versions"][0].contains("storage-table"));
}

TEST(ViewMetadataSerde, IgnoresUnknownFields) {
  auto json = ReadJsonResource("ViewMetadataV1Valid.json");
  json["future-field"] = 42;
  json["versions"][0]["future-version-field"] = "x";
  json["versions"][0]["representations"][0]["future-repr-field"] = true;

  auto metadata = ViewMetadataFromJson(json);
  ASSERT_THAT(metadata, IsOk());
  auto expected = ViewMetadataFromJson(ReadJsonResource("ViewMetadataV1Valid.json"));
  ASSERT_THAT(expected, IsOk());
  EXPECT_EQ(*metadata.value(), *expected.value());
}

TEST(ViewMetadataSerde, KeepsUnknownRepresentationType) {
  auto json = ReadJsonResource("ViewMetadataV1Valid.json");
  json["versions"][0]["representations"].push_back({{"type", "graphql"}});

  auto metadata = ViewMetadataFromJson(json);
  ASSERT_THAT(metadata, IsOk());
  auto version = metadata.value()->CurrentVersion();
  ASSERT_THAT(version, IsOk());
  ASSERT_EQ(version.value()->representations.size(), 2);
  EXPECT_EQ(version.value()->representations[1], (ViewRepresentation{.type = "graphql"}));

  auto serialized = ToJson(*metadata.value());
  ASSERT_THAT(serialized, IsOk());
  EXPECT_EQ(serialized.value()["versions"][0]["representations"][1],
            nlohmann::json({{"type", "graphql"}}));
}

TEST(ViewMetadataSerde, RejectsUnsupportedFormatVersion) {
  auto json = ReadJsonResource("ViewMetadataV1Valid.json");
  json["format-version"] = 2;
  EXPECT_THAT(ViewMetadataFromJson(json),
              HasErrorMessage("Cannot read unsupported view format version: 2"));
}

TEST(ViewMetadataSerde, RejectsMissingRequiredFields) {
  for (std::string key : {"view-uuid", "location", "current-version-id", "versions",
                          "version-log", "schemas"}) {
    auto json = ReadJsonResource("ViewMetadataV1Valid.json");
    json.erase(key);
    EXPECT_THAT(ViewMetadataFromJson(json), HasErrorMessage(key)) << key;
  }
  for (std::string key : {"version-id", "schema-id", "timestamp-ms", "summary",
                          "representations", "default-namespace"}) {
    auto json = ReadJsonResource("ViewMetadataV1Valid.json");
    json["versions"][0].erase(key);
    EXPECT_THAT(ViewMetadataFromJson(json), HasErrorMessage(key)) << key;
  }
}

TEST(ViewMetadataSerde, RejectsDanglingCurrentVersion) {
  auto json = ReadJsonResource("ViewMetadataV1Valid.json");
  json["current-version-id"] = 7;
  EXPECT_THAT(ViewMetadataFromJson(json),
              HasErrorMessage("Cannot find version with current-version-id=7"));
}

TEST(ViewUpdateSerde, RoundTripsEveryUpdateKind) {
  auto schema = std::make_shared<Schema>(
      std::vector<SchemaField>{SchemaField(1, "id", int32(), false)}, 1);
  std::vector<std::unique_ptr<ViewUpdate>> updates;
  updates.push_back(std::make_unique<view::AssignUUID>("uuid-1"));
  updates.push_back(std::make_unique<view::UpgradeFormatVersion>(1));
  updates.push_back(std::make_unique<view::AddSchema>(schema));
  updates.push_back(std::make_unique<view::SetLocation>("s3://bucket/view"));
  updates.push_back(std::make_unique<view::SetProperties>(
      std::unordered_map<std::string, std::string>{{"comment", "c"}}));
  updates.push_back(
      std::make_unique<view::RemoveProperties>(std::unordered_set<std::string>{"k"}));
  updates.push_back(std::make_unique<view::AddViewVersion>(MakeVersion(
      TableIdentifier{.ns = {.levels = {"default"}}, .name = "mv__storage"})));
  updates.push_back(std::make_unique<view::SetCurrentViewVersion>(
      view::SetCurrentViewVersion::kLastAdded));

  const std::vector<std::string> actions = {
      "assign-uuid",      "upgrade-format-version",  "add-schema",
      "set-location",     "set-properties",          "remove-properties",
      "add-view-version", "set-current-view-version"};
  ASSERT_EQ(updates.size(), actions.size());
  for (size_t i = 0; i < updates.size(); ++i) {
    auto json = ToJson(*updates[i]);
    ASSERT_THAT(json, IsOk()) << actions[i];
    EXPECT_EQ(json.value()["action"], actions[i]);
    auto parsed = ViewUpdateFromJson(json.value());
    ASSERT_THAT(parsed, IsOk()) << actions[i];
    EXPECT_EQ(*parsed.value(), *updates[i]) << actions[i];
  }
}

TEST(ViewUpdateSerde, WritesAddViewVersionWithStorageTable) {
  const view::AddViewVersion update(
      MakeVersion(TableIdentifier{.ns = {.levels = {"default"}}, .name = "mv__storage"}));
  auto json = ToJson(update);
  ASSERT_THAT(json, IsOk());
  EXPECT_EQ(json.value()["view-version"]["storage-table"],
            nlohmann::json({{"namespace", {"default"}}, {"name", "mv__storage"}}));
  EXPECT_EQ(json.value()["view-version"]["default-namespace"],
            nlohmann::json::array({"default"}));
  EXPECT_EQ(json.value()["view-version"]["default-catalog"], "prod");
}

TEST(ViewUpdateSerde, RejectsUnknownAction) {
  EXPECT_THAT(ViewUpdateFromJson({{"action", "add-spec"}}),
              HasErrorMessage("Unknown view update action: add-spec"));
}

TEST(ViewRequirementSerde, RoundTripsAssertViewUUID) {
  const view::AssertViewUUID requirement("uuid-1");
  auto json = ToJson(requirement);
  EXPECT_EQ(json, nlohmann::json({{"type", "assert-view-uuid"}, {"uuid", "uuid-1"}}));
  auto parsed = ViewRequirementFromJson(json);
  ASSERT_THAT(parsed, IsOk());
  EXPECT_EQ(*parsed.value(), requirement);
  EXPECT_THAT(ViewRequirementFromJson({{"type", "assert-table-uuid"}}),
              HasErrorMessage("Unknown view requirement type: assert-table-uuid"));
}

}  // namespace iceberg
