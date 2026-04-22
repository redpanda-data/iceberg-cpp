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

#include "iceberg/catalog/rest/auth/auth_manager.h"

#include <string>
#include <unordered_map>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include "iceberg/catalog/rest/auth/auth_managers.h"
#include "iceberg/catalog/rest/auth/auth_properties.h"
#include "iceberg/catalog/rest/auth/auth_session.h"
#include "iceberg/catalog/rest/auth/oauth2_util.h"
#include "iceberg/catalog/rest/http_client.h"
#include "iceberg/catalog/rest/json_serde_internal.h"
#include "iceberg/json_serde_internal.h"
#include "iceberg/result.h"
#include "iceberg/test/matchers.h"

namespace iceberg::rest::auth {

namespace {

/// Helper to parse OAuthTokenResponse from a JSON string.
Result<OAuthTokenResponse> ParseTokenResponse(const std::string& str) {
  ICEBERG_ASSIGN_OR_RAISE(auto json, iceberg::FromJsonString(str));
  return iceberg::rest::FromJson<OAuthTokenResponse>(json);
}

}  // namespace

class AuthManagerTest : public ::testing::Test {
 protected:
  HttpClient client_{{}};
};

// Verifies loading NoopAuthManager with explicit "none" auth type
TEST_F(AuthManagerTest, LoadNoopAuthManagerExplicit) {
  std::unordered_map<std::string, std::string> properties = {
      {AuthProperties::kAuthType, "none"}};

  auto manager_result = AuthManagers::Load("test-catalog", properties);
  ASSERT_THAT(manager_result, IsOk());

  auto session_result = manager_result.value()->CatalogSession(client_, properties);
  ASSERT_THAT(session_result, IsOk());

  std::unordered_map<std::string, std::string> headers;
  EXPECT_THAT(session_result.value()->Authenticate(headers), IsOk());
  EXPECT_TRUE(headers.empty());
}

// Verifies that NoopAuthManager is inferred when no auth properties are set
TEST_F(AuthManagerTest, LoadNoopAuthManagerInferred) {
  auto manager_result = AuthManagers::Load("test-catalog", {});
  ASSERT_THAT(manager_result, IsOk());
}

// Verifies that auth type is case-insensitive
TEST_F(AuthManagerTest, AuthTypeCaseInsensitive) {
  for (const auto& auth_type : {"NONE", "None", "NoNe"}) {
    std::unordered_map<std::string, std::string> properties = {
        {AuthProperties::kAuthType, auth_type}};
    EXPECT_THAT(AuthManagers::Load("test-catalog", properties), IsOk())
        << "Failed for auth type: " << auth_type;
  }
}

// Verifies that unknown auth type returns InvalidArgument
TEST_F(AuthManagerTest, UnknownAuthTypeReturnsInvalidArgument) {
  std::unordered_map<std::string, std::string> properties = {
      {AuthProperties::kAuthType, "unknown-auth-type"}};

  auto result = AuthManagers::Load("test-catalog", properties);
  EXPECT_THAT(result, IsError(ErrorKind::kInvalidArgument));
  EXPECT_THAT(result, HasErrorMessage("Unknown authentication type"));
}

// Verifies loading BasicAuthManager with valid credentials
TEST_F(AuthManagerTest, LoadBasicAuthManager) {
  std::unordered_map<std::string, std::string> properties = {
      {AuthProperties::kAuthType, "basic"},
      {AuthProperties::kBasicUsername, "admin"},
      {AuthProperties::kBasicPassword, "secret"}};

  auto manager_result = AuthManagers::Load("test-catalog", properties);
  ASSERT_THAT(manager_result, IsOk());

  auto session_result = manager_result.value()->CatalogSession(client_, properties);
  ASSERT_THAT(session_result, IsOk());

  std::unordered_map<std::string, std::string> headers;
  EXPECT_THAT(session_result.value()->Authenticate(headers), IsOk());
  // base64("admin:secret") == "YWRtaW46c2VjcmV0"
  EXPECT_EQ(headers["Authorization"], "Basic YWRtaW46c2VjcmV0");
}

// Verifies BasicAuthManager is case-insensitive for auth type
TEST_F(AuthManagerTest, BasicAuthTypeCaseInsensitive) {
  for (const auto& auth_type : {"BASIC", "Basic", "bAsIc"}) {
    std::unordered_map<std::string, std::string> properties = {
        {AuthProperties::kAuthType, auth_type},
        {AuthProperties::kBasicUsername, "user"},
        {AuthProperties::kBasicPassword, "pass"}};
    auto manager_result = AuthManagers::Load("test-catalog", properties);
    ASSERT_THAT(manager_result, IsOk()) << "Failed for auth type: " << auth_type;

    auto session_result = manager_result.value()->CatalogSession(client_, properties);
    ASSERT_THAT(session_result, IsOk()) << "Failed for auth type: " << auth_type;

    std::unordered_map<std::string, std::string> headers;
    EXPECT_THAT(session_result.value()->Authenticate(headers), IsOk());
    // base64("user:pass") == "dXNlcjpwYXNz"
    EXPECT_EQ(headers["Authorization"], "Basic dXNlcjpwYXNz");
  }
}

// Verifies BasicAuthManager fails when username is missing
TEST_F(AuthManagerTest, BasicAuthMissingUsername) {
  std::unordered_map<std::string, std::string> properties = {
      {AuthProperties::kAuthType, "basic"}, {AuthProperties::kBasicPassword, "secret"}};

  auto manager_result = AuthManagers::Load("test-catalog", properties);
  ASSERT_THAT(manager_result, IsOk());

  auto session_result = manager_result.value()->CatalogSession(client_, properties);
  EXPECT_THAT(session_result, IsError(ErrorKind::kInvalidArgument));
  EXPECT_THAT(session_result, HasErrorMessage("Missing required property"));
}

// Verifies BasicAuthManager fails when password is missing
TEST_F(AuthManagerTest, BasicAuthMissingPassword) {
  std::unordered_map<std::string, std::string> properties = {
      {AuthProperties::kAuthType, "basic"}, {AuthProperties::kBasicUsername, "admin"}};

  auto manager_result = AuthManagers::Load("test-catalog", properties);
  ASSERT_THAT(manager_result, IsOk());

  auto session_result = manager_result.value()->CatalogSession(client_, properties);
  EXPECT_THAT(session_result, IsError(ErrorKind::kInvalidArgument));
  EXPECT_THAT(session_result, HasErrorMessage("Missing required property"));
}

// Verifies BasicAuthManager handles special characters in credentials
TEST_F(AuthManagerTest, BasicAuthSpecialCharacters) {
  std::unordered_map<std::string, std::string> properties = {
      {AuthProperties::kAuthType, "basic"},
      {AuthProperties::kBasicUsername, "user@domain.com"},
      {AuthProperties::kBasicPassword, "p@ss:w0rd!"}};

  auto manager_result = AuthManagers::Load("test-catalog", properties);
  ASSERT_THAT(manager_result, IsOk());

  auto session_result = manager_result.value()->CatalogSession(client_, properties);
  ASSERT_THAT(session_result, IsOk());

  std::unordered_map<std::string, std::string> headers;
  EXPECT_THAT(session_result.value()->Authenticate(headers), IsOk());
  // base64("user@domain.com:p@ss:w0rd!") == "dXNlckBkb21haW4uY29tOnBAc3M6dzByZCE="
  EXPECT_EQ(headers["Authorization"], "Basic dXNlckBkb21haW4uY29tOnBAc3M6dzByZCE=");
}

// Verifies custom auth manager registration
TEST_F(AuthManagerTest, RegisterCustomAuthManager) {
  AuthManagers::Register(
      "custom",
      []([[maybe_unused]] std::string_view name,
         [[maybe_unused]] const std::unordered_map<std::string, std::string>& props)
          -> Result<std::unique_ptr<AuthManager>> {
        class CustomAuthManager : public AuthManager {
         public:
          Result<std::shared_ptr<AuthSession>> CatalogSession(
              HttpClient&, const std::unordered_map<std::string, std::string>&) override {
            return AuthSession::MakeDefault({{"X-Custom-Auth", "custom-value"}});
          }
        };
        return std::make_unique<CustomAuthManager>();
      });

  std::unordered_map<std::string, std::string> properties = {
      {AuthProperties::kAuthType, "custom"}};

  auto manager_result = AuthManagers::Load("test-catalog", properties);
  ASSERT_THAT(manager_result, IsOk());

  auto session_result = manager_result.value()->CatalogSession(client_, properties);
  ASSERT_THAT(session_result, IsOk());

  std::unordered_map<std::string, std::string> headers;
  EXPECT_THAT(session_result.value()->Authenticate(headers), IsOk());
  EXPECT_EQ(headers["X-Custom-Auth"], "custom-value");
}

// Verifies OAuth2 with static token
TEST_F(AuthManagerTest, OAuth2StaticToken) {
  std::unordered_map<std::string, std::string> properties = {
      {AuthProperties::kAuthType, "oauth2"},
      {AuthProperties::kToken.key(), "my-static-token"},
  };

  auto manager_result = AuthManagers::Load("test-catalog", properties);
  ASSERT_THAT(manager_result, IsOk());

  auto session_result = manager_result.value()->CatalogSession(client_, properties);
  ASSERT_THAT(session_result, IsOk());

  std::unordered_map<std::string, std::string> headers;
  EXPECT_THAT(session_result.value()->Authenticate(headers), IsOk());
  EXPECT_EQ(headers["Authorization"], "Bearer my-static-token");
}

// Verifies OAuth2 type is inferred from token property
TEST_F(AuthManagerTest, OAuth2InferredFromToken) {
  std::unordered_map<std::string, std::string> properties = {
      {AuthProperties::kToken.key(), "inferred-token"},
  };

  auto manager_result = AuthManagers::Load("test-catalog", properties);
  ASSERT_THAT(manager_result, IsOk());

  auto session_result = manager_result.value()->CatalogSession(client_, properties);
  ASSERT_THAT(session_result, IsOk());

  std::unordered_map<std::string, std::string> headers;
  EXPECT_THAT(session_result.value()->Authenticate(headers), IsOk());
  EXPECT_EQ(headers["Authorization"], "Bearer inferred-token");
}

// Verifies OAuth2 returns unauthenticated session when neither token nor credential is
// provided
TEST_F(AuthManagerTest, OAuth2MissingCredentials) {
  std::unordered_map<std::string, std::string> properties = {
      {AuthProperties::kAuthType, "oauth2"},
  };

  auto manager_result = AuthManagers::Load("test-catalog", properties);
  ASSERT_THAT(manager_result, IsOk());

  auto session_result = manager_result.value()->CatalogSession(client_, properties);
  ASSERT_THAT(session_result, IsOk());

  // Session should have no auth headers
  std::unordered_map<std::string, std::string> headers;
  ASSERT_TRUE(session_result.value()->Authenticate(headers).has_value());
  EXPECT_EQ(headers.find("Authorization"), headers.end());
}

// Verifies that when both token and credential are provided, token takes priority
// in CatalogSession (without a prior InitSession call)
TEST_F(AuthManagerTest, OAuth2TokenTakesPriorityOverCredential) {
  std::unordered_map<std::string, std::string> properties = {
      {AuthProperties::kAuthType, "oauth2"},
      {AuthProperties::kCredential.key(), "secret-only"},
      {AuthProperties::kToken.key(), "my-static-token"},
      {"uri", "http://localhost:8181"},
  };

  auto manager_result = AuthManagers::Load("test-catalog", properties);
  ASSERT_THAT(manager_result, IsOk());

  auto session_result = manager_result.value()->CatalogSession(client_, properties);
  ASSERT_THAT(session_result, IsOk());

  std::unordered_map<std::string, std::string> headers;
  ASSERT_THAT(session_result.value()->Authenticate(headers), IsOk());
  EXPECT_EQ(headers["Authorization"], "Bearer my-static-token");
}

// Verifies OAuthTokenResponse JSON parsing
TEST_F(AuthManagerTest, OAuthTokenResponseParsing) {
  std::string json = R"({
    "access_token": "test-access-token",
    "token_type": "bearer",
    "expires_in": 3600,
    "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
    "refresh_token": "test-refresh-token",
    "scope": "catalog"
  })";

  auto result = ParseTokenResponse(json);
  ASSERT_THAT(result, IsOk());
  EXPECT_EQ(result->access_token, "test-access-token");
  EXPECT_EQ(result->token_type, "bearer");
  ASSERT_TRUE(result->expires_in_secs.has_value());
  EXPECT_EQ(result->expires_in_secs.value(), 3600);
  EXPECT_EQ(result->issued_token_type, "urn:ietf:params:oauth:token-type:access_token");
  EXPECT_EQ(result->refresh_token, "test-refresh-token");
  EXPECT_EQ(result->scope, "catalog");
}

// Verifies OAuthTokenResponse parsing with minimal fields
TEST_F(AuthManagerTest, OAuthTokenResponseMinimal) {
  std::string json = R"({
    "access_token": "token123",
    "token_type": "Bearer"
  })";

  auto result = ParseTokenResponse(json);
  ASSERT_THAT(result, IsOk());
  EXPECT_EQ(result->access_token, "token123");
  EXPECT_EQ(result->token_type, "Bearer");
  EXPECT_FALSE(result->expires_in_secs.has_value());
  EXPECT_TRUE(result->issued_token_type.empty());
  EXPECT_TRUE(result->refresh_token.empty());
  EXPECT_TRUE(result->scope.empty());
}

// Verifies OAuthTokenResponse validation fails when access_token is missing
TEST_F(AuthManagerTest, OAuthTokenResponseMissingAccessToken) {
  std::string json = R"({"token_type": "bearer"})";
  auto result = ParseTokenResponse(json);
  EXPECT_THAT(result, ::testing::Not(IsOk()));
}

// Verifies OAuthTokenResponse validation fails when token_type is missing
TEST_F(AuthManagerTest, OAuthTokenResponseMissingTokenType) {
  std::string json = R"({"access_token": "token123"})";
  auto result = ParseTokenResponse(json);
  EXPECT_THAT(result, ::testing::Not(IsOk()));
}

// Verifies OAuthTokenResponse validation fails for unsupported token_type
TEST_F(AuthManagerTest, OAuthTokenResponseUnsupportedTokenType) {
  std::string json = R"({
    "access_token": "token123",
    "token_type": "mac"
  })";
  auto result = ParseTokenResponse(json);
  EXPECT_THAT(result, ::testing::Not(IsOk()));
}

// Verifies OAuthTokenResponse accepts N_A token type
TEST_F(AuthManagerTest, OAuthTokenResponseNATokenType) {
  std::string json = R"({
    "access_token": "token123",
    "token_type": "N_A"
  })";
  auto result = ParseTokenResponse(json);
  ASSERT_THAT(result, IsOk());
  EXPECT_EQ(result->token_type, "N_A");
}

// ---- SigV4 ----

#ifdef ICEBERG_REST_WITH_SIGV4

namespace {

std::unordered_map<std::string, std::string> MinimalSigV4Properties() {
  return {
      {AuthProperties::kAuthType, AuthProperties::kAuthTypeSigV4},
      {AuthProperties::kSigV4Region, "us-east-1"},
      {AuthProperties::kSigV4Service, "glue"},
      {AuthProperties::kSigV4AccessKeyId, "AKIAIOSFODNN7EXAMPLE"},
      {AuthProperties::kSigV4SecretAccessKey, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
  };
}

SignableRequest MakeGetRequest(std::string_view url) {
  return SignableRequest{
      .method = "GET", .url = url, .query_params = nullptr, .body = {}};
}

}  // namespace

// Verifies that auth type "sigv4" resolves to a real manager (no longer
// "NotImplemented") once credentials are supplied.
TEST_F(AuthManagerTest, LoadSigV4AuthManager) {
  auto properties = MinimalSigV4Properties();
  auto manager_result = AuthManagers::Load("test-catalog", properties);
  ASSERT_THAT(manager_result, IsOk());
  ASSERT_NE(manager_result.value(), nullptr);
}

// Verifies that "sigv4" auth type is case-insensitive.
TEST_F(AuthManagerTest, SigV4AuthTypeCaseInsensitive) {
  for (const auto& auth_type : {"SIGV4", "SigV4", "sIgV4"}) {
    auto properties = MinimalSigV4Properties();
    properties[AuthProperties::kAuthType] = auth_type;
    EXPECT_THAT(AuthManagers::Load("test-catalog", properties), IsOk())
        << "Failed for auth type: " << auth_type;
  }
}

// Required fields: missing region.
TEST_F(AuthManagerTest, SigV4MissingRegion) {
  auto properties = MinimalSigV4Properties();
  properties.erase(AuthProperties::kSigV4Region);
  auto result = AuthManagers::Load("test-catalog", properties);
  EXPECT_THAT(result, IsError(ErrorKind::kInvalidArgument));
}

// When the user explicitly requests the static provider but omits the
// access-key-id, we must reject the config (not silently fall back to the
// default chain).
TEST_F(AuthManagerTest, SigV4ExplicitStaticMissingAccessKeyId) {
  auto properties = MinimalSigV4Properties();
  properties.erase(AuthProperties::kSigV4AccessKeyId);
  properties[AuthProperties::kSigV4CredentialsProvider] =
      std::string(AuthProperties::kSigV4ProviderStatic);
  auto result = AuthManagers::Load("test-catalog", properties);
  EXPECT_THAT(result, IsError(ErrorKind::kInvalidArgument));
}

// Same for a missing secret: explicit static without the secret is an error.
TEST_F(AuthManagerTest, SigV4ExplicitStaticMissingSecretAccessKey) {
  auto properties = MinimalSigV4Properties();
  properties.erase(AuthProperties::kSigV4SecretAccessKey);
  properties[AuthProperties::kSigV4CredentialsProvider] =
      std::string(AuthProperties::kSigV4ProviderStatic);
  auto result = AuthManagers::Load("test-catalog", properties);
  EXPECT_THAT(result, IsError(ErrorKind::kInvalidArgument));
}

// Verifies that SigV4 signs a simple GET request and populates the expected
// AWS headers.
TEST_F(AuthManagerTest, SigV4SignsRequestHeaders) {
  auto properties = MinimalSigV4Properties();
  auto manager_result = AuthManagers::Load("test-catalog", properties);
  ASSERT_THAT(manager_result, IsOk());

  auto session_result = manager_result.value()->CatalogSession(client_, properties);
  ASSERT_THAT(session_result, IsOk());

  std::unordered_map<std::string, std::string> headers;
  auto request =
      MakeGetRequest("https://glue.us-east-1.amazonaws.com/iceberg/v1/namespaces");
  ASSERT_THAT(session_result.value()->Authenticate(request, headers), IsOk());

  EXPECT_TRUE(headers.contains("Authorization"));
  EXPECT_THAT(headers["Authorization"],
              ::testing::StartsWith("AWS4-HMAC-SHA256 Credential="));
  EXPECT_THAT(headers["Authorization"],
              ::testing::HasSubstr("/us-east-1/glue/aws4_request"));
  EXPECT_THAT(headers["Authorization"], ::testing::HasSubstr("SignedHeaders="));
  EXPECT_THAT(headers["Authorization"], ::testing::HasSubstr("Signature="));
  EXPECT_TRUE(headers.contains("X-Amz-Date"));
  // aws-c-auth emits this header lowercase (SigV4 spec uses lowercase in
  // canonical form; HTTP treats it case-insensitively on the wire).
  EXPECT_TRUE(headers.contains("x-amz-content-sha256"));
  // No session token supplied, so X-Amz-Security-Token must NOT be set.
  EXPECT_FALSE(headers.contains("X-Amz-Security-Token"));
}

// Verifies that the session_token surfaces as an X-Amz-Security-Token header
// on the signed request.
TEST_F(AuthManagerTest, SigV4IncludesSessionToken) {
  auto properties = MinimalSigV4Properties();
  properties[AuthProperties::kSigV4SessionToken] = "SESSION-TOKEN-12345";
  auto manager_result = AuthManagers::Load("test-catalog", properties);
  ASSERT_THAT(manager_result, IsOk());

  auto session_result = manager_result.value()->CatalogSession(client_, properties);
  ASSERT_THAT(session_result, IsOk());

  std::unordered_map<std::string, std::string> headers;
  auto request =
      MakeGetRequest("https://glue.us-east-1.amazonaws.com/iceberg/v1/namespaces");
  ASSERT_THAT(session_result.value()->Authenticate(request, headers), IsOk());

  ASSERT_TRUE(headers.contains("X-Amz-Security-Token"));
  EXPECT_EQ(headers["X-Amz-Security-Token"], "SESSION-TOKEN-12345");
}

// A SigV4 session rejects the headers-only Authenticate() overload — signing
// is impossible without request context.
TEST_F(AuthManagerTest, SigV4RejectsHeadersOnlyAuthenticate) {
  auto properties = MinimalSigV4Properties();
  auto manager_result = AuthManagers::Load("test-catalog", properties);
  ASSERT_THAT(manager_result, IsOk());
  auto session_result = manager_result.value()->CatalogSession(client_, properties);
  ASSERT_THAT(session_result, IsOk());
  std::unordered_map<std::string, std::string> headers;
  auto status = session_result.value()->Authenticate(headers);
  EXPECT_THAT(status, IsError(ErrorKind::kAuthenticationFailed));
}

// Using oauth2 as a SigV4 delegate: both the Bearer token (from OAuth) and
// the SigV4 signature flow through; SigV4 overwrites Authorization (matches
// the expected behaviour documented in the design).
TEST_F(AuthManagerTest, SigV4WithOAuth2Delegate) {
  auto properties = MinimalSigV4Properties();
  properties[AuthProperties::kSigV4DelegateAuthType] = AuthProperties::kAuthTypeOAuth2;
  properties[AuthProperties::kToken.key()] = "my-oauth-token";

  auto manager_result = AuthManagers::Load("test-catalog", properties);
  ASSERT_THAT(manager_result, IsOk());

  auto session_result = manager_result.value()->CatalogSession(client_, properties);
  ASSERT_THAT(session_result, IsOk());

  std::unordered_map<std::string, std::string> headers;
  auto request =
      MakeGetRequest("https://glue.us-east-1.amazonaws.com/iceberg/v1/namespaces");
  ASSERT_THAT(session_result.value()->Authenticate(request, headers), IsOk());

  // SigV4 replaces Authorization with its own AWS4 signature.
  EXPECT_THAT(headers["Authorization"],
              ::testing::StartsWith("AWS4-HMAC-SHA256 Credential="));
  EXPECT_TRUE(headers.contains("X-Amz-Date"));
}

// Recursive delegate (sigv4 wrapping sigv4) is rejected.
TEST_F(AuthManagerTest, SigV4RejectsRecursiveDelegate) {
  auto properties = MinimalSigV4Properties();
  properties[AuthProperties::kSigV4DelegateAuthType] = AuthProperties::kAuthTypeSigV4;
  auto result = AuthManagers::Load("test-catalog", properties);
  EXPECT_THAT(result, IsError(ErrorKind::kInvalidArgument));
}

// Default credentials chain (env → profile → STS Web Identity → IMDS) can be
// selected explicitly. We only verify that the manager loads and returns a
// session — actually signing with the default chain would require real AWS
// credentials in the test environment.
TEST_F(AuthManagerTest, SigV4DefaultCredentialsProviderLoads) {
  std::unordered_map<std::string, std::string> properties = {
      {AuthProperties::kAuthType, AuthProperties::kAuthTypeSigV4},
      {AuthProperties::kSigV4Region, "us-east-1"},
      {AuthProperties::kSigV4Service, "glue"},
      {AuthProperties::kSigV4CredentialsProvider,
       std::string(AuthProperties::kSigV4ProviderDefault)},
  };
  auto manager_result = AuthManagers::Load("test-catalog", properties);
  ASSERT_THAT(manager_result, IsOk());
  auto session_result = manager_result.value()->CatalogSession(client_, properties);
  ASSERT_THAT(session_result, IsOk());
}

// Without an access-key-id and without an explicit provider, auto-detection
// picks the default chain — catalog loads successfully.
TEST_F(AuthManagerTest, SigV4AutoSelectsDefaultWhenNoStaticKeys) {
  std::unordered_map<std::string, std::string> properties = {
      {AuthProperties::kAuthType, AuthProperties::kAuthTypeSigV4},
      {AuthProperties::kSigV4Region, "us-east-1"},
      {AuthProperties::kSigV4Service, "glue"},
  };
  auto manager_result = AuthManagers::Load("test-catalog", properties);
  ASSERT_THAT(manager_result, IsOk());
}

// Unknown credentials-provider value is rejected.
TEST_F(AuthManagerTest, SigV4UnknownCredentialsProvider) {
  auto properties = MinimalSigV4Properties();
  properties[AuthProperties::kSigV4CredentialsProvider] = "iam";
  auto result = AuthManagers::Load("test-catalog", properties);
  EXPECT_THAT(result, IsError(ErrorKind::kInvalidArgument));
}

#endif  // ICEBERG_REST_WITH_SIGV4

}  // namespace iceberg::rest::auth
