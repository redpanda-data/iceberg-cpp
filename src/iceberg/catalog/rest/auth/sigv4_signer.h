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

#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>

#include "iceberg/catalog/rest/auth/auth_session.h"
#include "iceberg/catalog/rest/iceberg_rest_export.h"
#include "iceberg/result.h"

/// \file iceberg/catalog/rest/auth/sigv4_signer.h
/// \brief AWS Signature V4 request signer for the REST catalog.
///
/// Wraps aws-crt-cpp's Sigv4HttpRequestSigner so callers can ask "what
/// headers do I need to add to this HTTP request so AWS accepts it?"
/// without depending on aws-crt-cpp types directly.

namespace iceberg::rest::auth {

/// \brief Which credential source the signer should use.
enum class SigV4CredentialsProvider {
  /// Static access-key / secret-access-key (/ optional session-token) from
  /// config. Best for tests and short-lived scripts.
  kStatic,
  /// aws-crt-cpp's SDK-standard default chain, cached:
  ///   Environment → Profile → STS Web Identity (IRSA) → IMDSv2 / ECS.
  /// Credentials are refreshed automatically by aws-crt-cpp before expiry.
  /// Best for EC2/EKS/ECS deployments and AWS Glue integration.
  kDefault,
};

/// \brief SigV4 signing configuration.
struct SigV4Config {
  /// AWS region (e.g., "us-east-1"). Required.
  std::string region;
  /// AWS signing service name. "glue" for AWS Glue's Iceberg REST endpoint;
  /// "execute-api" for API Gateway; "s3tables" for S3 Tables. Required.
  std::string service;
  /// Which credential source the signer should consult.
  SigV4CredentialsProvider provider = SigV4CredentialsProvider::kStatic;
  /// Static AWS access key ID. Required when ``provider == kStatic``.
  std::string access_key_id;
  /// Static AWS secret access key. Required when ``provider == kStatic``.
  std::string secret_access_key;
  /// Optional STS session token. When present, X-Amz-Security-Token is
  /// added to the request and included in the signed header set.
  /// Only consulted when ``provider == kStatic``.
  std::string session_token;
};

/// \brief Computes SigV4 headers for outgoing HTTP requests.
///
/// Thread-safe after construction.
class ICEBERG_REST_EXPORT SigV4Signer {
 public:
  /// \brief Construct a signer. Validates that required config fields are set.
  static Result<std::shared_ptr<SigV4Signer>> Make(SigV4Config config);

  /// \brief Construct a signer that pins every Sign() call to a fixed UTC
  ///        timestamp. Intended strictly for deterministic unit tests
  ///        (canonical SigV4 test vectors) — production callers MUST use
  ///        ``Make`` so the signing time stays in sync with the host clock.
  static Result<std::shared_ptr<SigV4Signer>> MakeForTests(
      SigV4Config config, std::chrono::system_clock::time_point signing_time);

  ~SigV4Signer();
  SigV4Signer(const SigV4Signer&) = delete;
  SigV4Signer& operator=(const SigV4Signer&) = delete;

  /// \brief Compute the SigV4 headers for a request.
  ///
  /// \param request The method/URL/query/body to sign.
  /// \param existing_headers Headers already set on the request (e.g., a
  ///        delegate auth manager may have added "Authorization: Bearer ...";
  ///        that header MUST be part of the signed header set).
  /// \return The headers that the caller should insert_or_assign onto the
  ///         outgoing request to carry the signature. Typically
  ///         ``Authorization``, ``X-Amz-Date``, ``X-Amz-Content-Sha256``,
  ///         ``Host`` (if it wasn't in ``existing_headers``), and
  ///         ``X-Amz-Security-Token`` (if session_token is configured).
  Result<std::unordered_map<std::string, std::string>> Sign(
      const SignableRequest& request,
      const std::unordered_map<std::string, std::string>& existing_headers) const;

 private:
  class Impl;
  explicit SigV4Signer(std::unique_ptr<Impl> impl);
  std::unique_ptr<Impl> impl_;
};

}  // namespace iceberg::rest::auth
