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

#include "iceberg/catalog/rest/auth/sigv4_signer.h"

#include <chrono>
#include <string>
#include <unordered_map>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "iceberg/catalog/rest/auth/auth_session.h"
#include "iceberg/test/matchers.h"

/// SigV4 canonical-vector tests.
///
/// The expected ``Authorization`` headers in these tests were computed by an
/// independent reference implementation (Python botocore 1.37's
/// ``SigV4Auth``) against the same inputs our signer sees, with the signing
/// time pinned to 2015-08-30T12:36:00Z. The generator script lives at
/// ``/tmp/gen_sigv4_vectors.py`` in the development setup; rerunning it with
/// the same inputs reproduces these exact signatures.
///
/// Purpose: catch regressions in how we wrap aws-crt-cpp (wrong service
/// name, wrong region, wrong double-URI-encoding flag, missing
/// x-amz-content-sha256 header, etc.) — such regressions would change the
/// ``Authorization`` header bytes and fail these tests, whereas the
/// "headers present + start with AWS4-HMAC-SHA256" assertions in
/// auth_manager_test.cc would still pass.

namespace iceberg::rest::auth {

namespace {

constexpr const char* kAccessKey = "AKIDEXAMPLE";
constexpr const char* kSecretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
constexpr const char* kRegion = "us-east-1";
constexpr const char* kService = "glue";
constexpr const char* kHost = "glue.us-east-1.amazonaws.com";

/// 2015-08-30T12:36:00Z — matches the timestamp used when generating the
/// expected Authorization headers.
std::chrono::system_clock::time_point FixedSigningTime() {
  return std::chrono::system_clock::time_point(std::chrono::seconds(1440938160));
}

SigV4Config DefaultConfig() {
  return SigV4Config{
      .region = kRegion,
      .service = kService,
      .provider = SigV4CredentialsProvider::kStatic,
      .access_key_id = kAccessKey,
      .secret_access_key = kSecretKey,
      .session_token = "",
  };
}

}  // namespace

// -----------------------------------------------------------------------------
// GET, empty body, no query params.
TEST(SigV4SignerTest, CanonicalVectorGetVanilla) {
  auto signer_result = SigV4Signer::MakeForTests(DefaultConfig(), FixedSigningTime());
  ASSERT_THAT(signer_result, IsOk());

  std::string url = "https://glue.us-east-1.amazonaws.com/iceberg/v1/config";
  SignableRequest request{
      .method = "GET",
      .url = url,
      .query_params = nullptr,
      .body = {},
  };
  std::unordered_map<std::string, std::string> existing{{"Host", kHost}};

  auto result = signer_result.value()->Sign(request, existing);
  ASSERT_THAT(result, IsOk());

  EXPECT_EQ(result->at("X-Amz-Date"), "20150830T123600Z");
  EXPECT_EQ(result->at("x-amz-content-sha256"),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  EXPECT_EQ(result->at("Authorization"),
            "AWS4-HMAC-SHA256 "
            "Credential=AKIDEXAMPLE/20150830/us-east-1/glue/aws4_request, "
            "SignedHeaders=host;x-amz-content-sha256;x-amz-date, "
            "Signature="
            "029d943d26726020757da405ee50a23ab8e28649d845d5bf69717d7246cd3f87");
}

// -----------------------------------------------------------------------------
// GET with query parameters.
TEST(SigV4SignerTest, CanonicalVectorGetWithQuery) {
  auto signer_result = SigV4Signer::MakeForTests(DefaultConfig(), FixedSigningTime());
  ASSERT_THAT(signer_result, IsOk());

  std::string url = "https://glue.us-east-1.amazonaws.com/iceberg/v1/namespaces";
  std::unordered_map<std::string, std::string> query_params{
      {"parent", "default"},
      {"pageSize", "10"},
  };
  SignableRequest request{
      .method = "GET",
      .url = url,
      .query_params = &query_params,
      .body = {},
  };
  std::unordered_map<std::string, std::string> existing{{"Host", kHost}};

  auto result = signer_result.value()->Sign(request, existing);
  ASSERT_THAT(result, IsOk());

  EXPECT_EQ(result->at("X-Amz-Date"), "20150830T123600Z");
  EXPECT_EQ(result->at("x-amz-content-sha256"),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  EXPECT_EQ(result->at("Authorization"),
            "AWS4-HMAC-SHA256 "
            "Credential=AKIDEXAMPLE/20150830/us-east-1/glue/aws4_request, "
            "SignedHeaders=host;x-amz-content-sha256;x-amz-date, "
            "Signature="
            "e82f9da81e1f789f7d55aae636026b6df73a0c23fd3ba08b6d4a7d4e01c1062c");
}

// -----------------------------------------------------------------------------
// POST with a JSON body and a Content-Type header in the signed set.
TEST(SigV4SignerTest, CanonicalVectorPostJsonBody) {
  auto signer_result = SigV4Signer::MakeForTests(DefaultConfig(), FixedSigningTime());
  ASSERT_THAT(signer_result, IsOk());

  std::string url = "https://glue.us-east-1.amazonaws.com/iceberg/v1/namespaces";
  std::string body = R"({"namespace":["default"],"properties":{}})";
  SignableRequest request{
      .method = "POST",
      .url = url,
      .query_params = nullptr,
      .body = body,
  };
  std::unordered_map<std::string, std::string> existing{
      {"Host", kHost},
      {"Content-Type", "application/json"},
  };

  auto result = signer_result.value()->Sign(request, existing);
  ASSERT_THAT(result, IsOk());

  EXPECT_EQ(result->at("X-Amz-Date"), "20150830T123600Z");
  EXPECT_EQ(result->at("x-amz-content-sha256"),
            "6a2d107daab05b4284e65fac424da4093a29ad3c9726c6f3e8bf85d5daeb0e34");
  EXPECT_EQ(result->at("Authorization"),
            "AWS4-HMAC-SHA256 "
            "Credential=AKIDEXAMPLE/20150830/us-east-1/glue/aws4_request, "
            "SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date, "
            "Signature="
            "d4c36f6140f60082617e086c3945701678f24db257724d9c6392962885ecb099");
}

// -----------------------------------------------------------------------------
// Sanity: two successive signs of the same request with the same pinned
// timestamp produce byte-identical output. Proves our impl is deterministic
// given fixed inputs (the credentials provider is not re-fetched, the
// timestamp is honored, nothing ambient leaks in).
TEST(SigV4SignerTest, DeterministicWithFixedTimestamp) {
  auto signer_result = SigV4Signer::MakeForTests(DefaultConfig(), FixedSigningTime());
  ASSERT_THAT(signer_result, IsOk());

  std::string url = "https://glue.us-east-1.amazonaws.com/iceberg/v1/config";
  SignableRequest request{
      .method = "GET",
      .url = url,
      .query_params = nullptr,
      .body = {},
  };
  std::unordered_map<std::string, std::string> existing{{"Host", kHost}};

  auto r1 = signer_result.value()->Sign(request, existing);
  auto r2 = signer_result.value()->Sign(request, existing);
  ASSERT_THAT(r1, IsOk());
  ASSERT_THAT(r2, IsOk());
  EXPECT_EQ(r1->at("Authorization"), r2->at("Authorization"));
  EXPECT_EQ(r1->at("X-Amz-Date"), r2->at("X-Amz-Date"));
}

}  // namespace iceberg::rest::auth
