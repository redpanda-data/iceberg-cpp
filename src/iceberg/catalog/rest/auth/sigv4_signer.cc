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

#include <array>
#include <future>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

#include <aws/crt/Api.h>
#include <aws/crt/Types.h>
#include <aws/crt/auth/Credentials.h>
#include <aws/crt/auth/Signing.h>
#include <aws/crt/auth/Sigv4Signing.h>
#include <aws/crt/http/HttpRequestResponse.h>
#include <openssl/sha.h>

#include "iceberg/catalog/rest/auth/auth_manager.h"
#include "iceberg/catalog/rest/auth/auth_manager_internal.h"
#include "iceberg/catalog/rest/auth/auth_managers.h"
#include "iceberg/catalog/rest/auth/auth_properties.h"
#include "iceberg/util/macros.h"

namespace iceberg::rest::auth {

namespace {

/// aws-crt-cpp requires a single ApiHandle alive for the lifetime of any CRT
/// user — it initializes aws-c-common / aws-c-io / etc. Use a function-local
/// static so it's lazily constructed on first use and destroyed at exit.
Aws::Crt::ApiHandle& GlobalApiHandle() {
  static Aws::Crt::ApiHandle handle;
  return handle;
}

std::string Sha256Hex(std::string_view data) {
  std::array<unsigned char, SHA256_DIGEST_LENGTH> digest{};
  ::SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(),
           digest.data());
  static constexpr std::string_view kHex = "0123456789abcdef";
  std::string out(SHA256_DIGEST_LENGTH * 2, '\0');
  for (size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
    out[2 * i] = kHex[digest[i] >> 4];
    out[2 * i + 1] = kHex[digest[i] & 0x0F];
  }
  return out;
}

/// Extracts host[:port] from a URL like "https://host:port/path?q=1".
std::string_view ExtractHost(std::string_view url) {
  auto scheme_end = url.find("://");
  std::string_view rest =
      (scheme_end == std::string_view::npos) ? url : url.substr(scheme_end + 3);
  auto slash = rest.find('/');
  if (slash != std::string_view::npos) rest = rest.substr(0, slash);
  auto q = rest.find('?');
  if (q != std::string_view::npos) rest = rest.substr(0, q);
  return rest;
}

/// Extracts the path (and any inline query string) from a URL; returns "/" if
/// none is present. The caller must append its own query_params separately.
std::string_view ExtractPath(std::string_view url) {
  auto scheme_end = url.find("://");
  std::string_view rest =
      (scheme_end == std::string_view::npos) ? url : url.substr(scheme_end + 3);
  auto slash = rest.find('/');
  if (slash == std::string_view::npos) {
    return {"/"};
  }
  return rest.substr(slash);
}

bool EqualsIgnoreCase(std::string_view a, std::string_view b) {
  if (a.size() != b.size()) return false;
  for (size_t i = 0; i < a.size(); ++i) {
    auto lower = [](char c) {
      return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c;
    };
    if (lower(a[i]) != lower(b[i])) return false;
  }
  return true;
}

std::string ByteCursorToStdString(Aws::Crt::ByteCursor bc) {
  return {reinterpret_cast<const char*>(bc.ptr), bc.len};
}

}  // namespace

class SigV4Signer::Impl {
 public:
  Impl(SigV4Config config, std::shared_ptr<Aws::Crt::Auth::ICredentialsProvider> provider,
       std::optional<std::chrono::system_clock::time_point> fixed_time)
      : config_(std::move(config)),
        provider_(std::move(provider)),
        fixed_time_(fixed_time) {}

  const SigV4Config& config() const { return config_; }
  const std::shared_ptr<Aws::Crt::Auth::ICredentialsProvider>& provider() const {
    return provider_;
  }
  const std::optional<std::chrono::system_clock::time_point>& fixed_time() const {
    return fixed_time_;
  }

 private:
  SigV4Config config_;
  std::shared_ptr<Aws::Crt::Auth::ICredentialsProvider> provider_;
  /// When set, overrides the signing timestamp (tests only).
  std::optional<std::chrono::system_clock::time_point> fixed_time_;
};

SigV4Signer::SigV4Signer(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}
SigV4Signer::~SigV4Signer() = default;

namespace {

/// Builds the aws-crt-cpp credentials provider matching the SigV4Config.
/// For the default chain we explicitly pass the static default ClientBootstrap
/// so aws-crt-cpp can make network calls for IMDS / STS Web Identity.
Result<std::shared_ptr<Aws::Crt::Auth::ICredentialsProvider>> BuildCredentialsProvider(
    const SigV4Config& config) {
  namespace Auth = Aws::Crt::Auth;
  switch (config.provider) {
    case SigV4CredentialsProvider::kStatic: {
      if (config.access_key_id.empty() || config.secret_access_key.empty()) {
        return InvalidArgument(
            "SigV4: static provider requires access-key-id and secret-access-key");
      }
      Auth::CredentialsProviderStaticConfig static_cfg;
      static_cfg.AccessKeyId =
          Aws::Crt::ByteCursorFromCString(config.access_key_id.c_str());
      static_cfg.SecretAccessKey =
          Aws::Crt::ByteCursorFromCString(config.secret_access_key.c_str());
      if (!config.session_token.empty()) {
        static_cfg.SessionToken =
            Aws::Crt::ByteCursorFromCString(config.session_token.c_str());
      }
      auto provider =
          Auth::CredentialsProvider::CreateCredentialsProviderStatic(static_cfg);
      if (!provider) {
        return AuthenticationFailed("SigV4: failed to build static credentials provider");
      }
      return provider;
    }
    case SigV4CredentialsProvider::kDefault: {
      Auth::CredentialsProviderChainDefaultConfig chain_cfg;
      // The API handle we keep alive for the process owns the default
      // ClientBootstrap / EventLoopGroup / HostResolver. The default chain
      // needs them to reach IMDS and STS.
      chain_cfg.Bootstrap =
          Aws::Crt::ApiHandle::GetOrCreateStaticDefaultClientBootstrap();
      if (chain_cfg.Bootstrap == nullptr) {
        return IOError(
            "SigV4: could not create default ClientBootstrap for credentials chain");
      }
      auto provider =
          Auth::CredentialsProvider::CreateCredentialsProviderChainDefault(chain_cfg);
      if (!provider) {
        return AuthenticationFailed(
            "SigV4: failed to build default credentials provider chain");
      }
      return provider;
    }
  }
  return InvalidArgument("SigV4: unknown credentials provider");
}

}  // namespace

Result<std::shared_ptr<SigV4Signer>> SigV4Signer::Make(SigV4Config config) {
  if (config.region.empty()) {
    return InvalidArgument("SigV4: region is required");
  }
  if (config.service.empty()) {
    return InvalidArgument("SigV4: service is required");
  }
  GlobalApiHandle();
  ICEBERG_ASSIGN_OR_RAISE(auto provider, BuildCredentialsProvider(config));
  return std::shared_ptr<SigV4Signer>(new SigV4Signer(
      std::make_unique<Impl>(std::move(config), std::move(provider), std::nullopt)));
}

Result<std::shared_ptr<SigV4Signer>> SigV4Signer::MakeForTests(
    SigV4Config config, std::chrono::system_clock::time_point signing_time) {
  if (config.region.empty()) {
    return InvalidArgument("SigV4: region is required");
  }
  if (config.service.empty()) {
    return InvalidArgument("SigV4: service is required");
  }
  GlobalApiHandle();
  ICEBERG_ASSIGN_OR_RAISE(auto provider, BuildCredentialsProvider(config));
  return std::shared_ptr<SigV4Signer>(new SigV4Signer(
      std::make_unique<Impl>(std::move(config), std::move(provider), signing_time)));
}

Result<std::unordered_map<std::string, std::string>> SigV4Signer::Sign(
    const SignableRequest& request,
    const std::unordered_map<std::string, std::string>& existing_headers) const {
  namespace Crt = Aws::Crt;
  namespace Auth = Aws::Crt::Auth;
  namespace Http = Aws::Crt::Http;

  const SigV4Config& cfg = impl_->config();

  auto req = std::make_shared<Http::HttpRequest>();
  if (!*req) {
    return IOError("SigV4: failed to allocate HttpRequest");
  }

  // Build "path?k=v&k=v" from the URL and any query_params. aws-crt-cpp will
  // URI-encode per its double-encode setting, so we pass raw values here.
  std::string path_and_query(ExtractPath(request.url));
  if (request.query_params != nullptr && !request.query_params->empty()) {
    bool already_has_query = path_and_query.find('?') != std::string::npos;
    path_and_query.push_back(already_has_query ? '&' : '?');
    bool first = true;
    for (const auto& [k, v] : *request.query_params) {
      if (!first) path_and_query.push_back('&');
      first = false;
      path_and_query.append(k).push_back('=');
      path_and_query.append(v);
    }
  }

  const std::string method(request.method);
  req->SetMethod(Crt::ByteCursorFromCString(method.c_str()));
  req->SetPath(Crt::ByteCursorFromCString(path_and_query.c_str()));

  // Keep header name/value storage alive until AddHeader has copied them.
  // (aws-c-http copies internally, but we keep the strings around during the
  // loop to be safe against future library changes.)
  //
  // aws-c-auth rejects requests that already contain any header it plans to
  // add itself (Authorization, X-Amz-Date, X-Amz-Content-Sha256,
  // X-Amz-Security-Token). When a delegate auth session has added
  // "Authorization: Bearer ...", we rename it to a non-conflicting header so
  // (a) the delegate's credential is still covered by the SigV4 signature,
  // and (b) aws-c-auth can add its own Authorization header with the
  // signature. This mirrors the Java Iceberg RESTSigV4AuthSession's rename
  // to X-Iceberg-Access-Delegation.
  static constexpr std::string_view kDelegatedAuthHeader = "X-Iceberg-Access-Delegation";
  std::vector<std::pair<std::string, std::string>> header_storage;
  header_storage.reserve(existing_headers.size() + 1);
  bool has_host = false;
  for (const auto& [k, v] : existing_headers) {
    if (EqualsIgnoreCase(k, "Authorization")) {
      header_storage.emplace_back(std::string(kDelegatedAuthHeader), v);
    } else {
      header_storage.emplace_back(k, v);
    }
    if (EqualsIgnoreCase(k, "host")) has_host = true;
  }
  if (!has_host) {
    header_storage.emplace_back("Host", std::string(ExtractHost(request.url)));
  }

  std::unordered_set<std::string> pre_signed_header_names;
  pre_signed_header_names.reserve(header_storage.size());
  for (const auto& [k, v] : header_storage) {
    Http::HttpHeader h{};
    h.name = Crt::ByteCursorFromCString(k.c_str());
    h.value = Crt::ByteCursorFromCString(v.c_str());
    req->AddHeader(h);
    pre_signed_header_names.insert(k);
  }

  // Build signing config.
  Auth::AwsSigningConfig signing_config;
  signing_config.SetSigningAlgorithm(Auth::SigningAlgorithm::SigV4);
  signing_config.SetSignatureType(Auth::SignatureType::HttpRequestViaHeaders);
  signing_config.SetRegion(Crt::String(cfg.region.begin(), cfg.region.end()));
  signing_config.SetService(Crt::String(cfg.service.begin(), cfg.service.end()));
  // Glue and most AWS services (non-S3) double-encode the URI path in the
  // canonical request; S3 is the sole exception. We target non-S3 so set true.
  signing_config.SetUseDoubleUriEncode(true);
  signing_config.SetShouldNormalizeUriPath(true);
  // Explicit payload hash — always emit the header, compute it ourselves so we
  // don't depend on the library's payload-stream handling (Java Iceberg hit
  // correctness bugs around empty-body SDK defaults; PR apache/iceberg#6951).
  const std::string payload_hash = Sha256Hex(request.body);
  signing_config.SetSignedBodyValue(
      Crt::String(payload_hash.begin(), payload_hash.end()));
  signing_config.SetSignedBodyHeader(Auth::SignedBodyHeaderType::XAmzContentSha256);

  // Test-only: pin the signing timestamp so we can reproduce AWS's
  // canonical test vectors bytewise. In production the default is
  // "now", which is what we want.
  if (impl_->fixed_time().has_value()) {
    signing_config.SetSigningTimepoint(Aws::Crt::DateTime(*impl_->fixed_time()));
  }

  // Hand aws-crt-cpp the credentials provider. For the default chain this is
  // where Environment / Profile / STS Web Identity / IMDS resolution happens,
  // transparently cached and refreshed inside aws-c-auth.
  signing_config.SetCredentialsProvider(impl_->provider());

  // Sign. For a static provider the callback fires synchronously; for IMDS /
  // STS the first call blocks while the provider fetches credentials (then
  // caches them until near expiry). Either way we wrap in a promise so the
  // public API stays sync.
  Auth::Sigv4HttpRequestSigner signer;
  std::promise<int> promise;
  auto future = promise.get_future();
  const bool scheduled = signer.SignRequest(
      req, signing_config,
      [&promise](const std::shared_ptr<Http::HttpRequest>& /*signed_req*/,
                 int error_code) { promise.set_value(error_code); });
  if (!scheduled) {
    return AuthenticationFailed(
        "SigV4: Sigv4HttpRequestSigner::SignRequest failed to "
        "schedule signing");
  }
  const int error_code = future.get();
  if (error_code != 0) {
    return AuthenticationFailed("SigV4: signing failed (aws error {})", error_code);
  }

  // Collect headers that the signer added (anything not already in
  // `existing_headers`). These are what the HTTP client needs to append.
  std::unordered_map<std::string, std::string> out;
  const size_t header_count = req->GetHeaderCount();
  for (size_t i = 0; i < header_count; ++i) {
    auto header_opt = req->GetHeader(i);
    if (!header_opt.has_value()) continue;
    const Http::HttpHeader& h = header_opt.value();
    std::string name = ByteCursorToStdString(h.name);
    if (pre_signed_header_names.contains(name)) {
      continue;
    }
    out.emplace(std::move(name), ByteCursorToStdString(h.value));
  }
  return out;
}

// ---------------------------------------------------------------------------
// SigV4 AuthManager + AuthSession (registered below via MakeSigV4Manager).

namespace {

/// \brief AuthSession that signs each outgoing request with AWS SigV4.
///
/// If ``delegate`` is non-null, it is invoked first so its headers (e.g.,
/// ``Authorization: Bearer <token>`` added by OAuth2) participate in the
/// signed header set — matching the behaviour of Java Iceberg's
/// ``RESTSigV4AuthSession``. SigV4 then overwrites ``Authorization`` with
/// its own signature, so the delegate header is covered by the signature
/// but not visible to the server as a second auth scheme.
class SigV4AuthSession : public AuthSession {
 public:
  SigV4AuthSession(std::shared_ptr<SigV4Signer> signer,
                   std::shared_ptr<AuthSession> delegate)
      : signer_(std::move(signer)), delegate_(std::move(delegate)) {}

  Status Authenticate(
      [[maybe_unused]] std::unordered_map<std::string, std::string>& headers) override {
    // Header-only signing is impossible for SigV4 (we need method/url/body).
    // Callers routed through HttpClient always use the SignableRequest
    // overload below; reaching here indicates a caller that does not plumb
    // request context.
    return AuthenticationFailed(
        "SigV4 requires request context; call Authenticate(SignableRequest, headers).");
  }

  Status Authenticate(const SignableRequest& request,
                      std::unordered_map<std::string, std::string>& headers) override {
    if (delegate_) {
      ICEBERG_RETURN_UNEXPECTED(delegate_->Authenticate(request, headers));
    }
    ICEBERG_ASSIGN_OR_RAISE(auto signed_headers, signer_->Sign(request, headers));
    for (auto& [k, v] : signed_headers) {
      headers.insert_or_assign(std::move(k), std::move(v));
    }
    return {};
  }

  Status Close() override {
    if (delegate_) {
      return delegate_->Close();
    }
    return {};
  }

 private:
  std::shared_ptr<SigV4Signer> signer_;
  std::shared_ptr<AuthSession> delegate_;
};

/// \brief Manager that constructs SigV4AuthSessions for a REST catalog.
class SigV4Manager : public AuthManager {
 public:
  SigV4Manager(std::shared_ptr<SigV4Signer> signer, std::unique_ptr<AuthManager> delegate)
      : signer_(std::move(signer)), delegate_(std::move(delegate)) {}

  Result<std::shared_ptr<AuthSession>> InitSession(
      HttpClient& init_client,
      const std::unordered_map<std::string, std::string>& properties) override {
    std::shared_ptr<AuthSession> delegate_session;
    if (delegate_) {
      ICEBERG_ASSIGN_OR_RAISE(delegate_session,
                              delegate_->InitSession(init_client, properties));
    }
    return std::make_shared<SigV4AuthSession>(signer_, std::move(delegate_session));
  }

  Result<std::shared_ptr<AuthSession>> CatalogSession(
      HttpClient& client,
      const std::unordered_map<std::string, std::string>& properties) override {
    std::shared_ptr<AuthSession> delegate_session;
    if (delegate_) {
      ICEBERG_ASSIGN_OR_RAISE(delegate_session,
                              delegate_->CatalogSession(client, properties));
    }
    return std::make_shared<SigV4AuthSession>(signer_, std::move(delegate_session));
  }

  Status Close() override {
    if (delegate_) {
      return delegate_->Close();
    }
    return {};
  }

 private:
  std::shared_ptr<SigV4Signer> signer_;
  std::unique_ptr<AuthManager> delegate_;
};

std::string GetOr(const std::unordered_map<std::string, std::string>& properties,
                  const std::string& key, std::string_view fallback) {
  auto it = properties.find(key);
  if (it == properties.end() || it->second.empty()) {
    return std::string(fallback);
  }
  return it->second;
}

/// Resolve the credentials provider enum from the property value.
/// Auto-detects when the property is unset: static if an access key is
/// configured, default chain otherwise.
Result<SigV4CredentialsProvider> ResolveCredentialsProvider(std::string_view raw,
                                                            bool have_static_keys) {
  if (raw.empty()) {
    return have_static_keys ? SigV4CredentialsProvider::kStatic
                            : SigV4CredentialsProvider::kDefault;
  }
  if (raw == AuthProperties::kSigV4ProviderStatic) {
    return SigV4CredentialsProvider::kStatic;
  }
  if (raw == AuthProperties::kSigV4ProviderDefault) {
    return SigV4CredentialsProvider::kDefault;
  }
  return InvalidArgument(
      "SigV4: unsupported credentials-provider '{}' (expected 'static' or 'default')",
      raw);
}

}  // namespace

Result<std::unique_ptr<AuthManager>> MakeSigV4Manager(
    std::string_view name,
    const std::unordered_map<std::string, std::string>& properties) {
  SigV4Config sigv4_config;
  sigv4_config.region = GetOr(properties, AuthProperties::kSigV4Region, "");
  sigv4_config.service = GetOr(properties, AuthProperties::kSigV4Service,
                               AuthProperties::kSigV4DefaultService);
  sigv4_config.access_key_id = GetOr(properties, AuthProperties::kSigV4AccessKeyId, "");
  sigv4_config.secret_access_key =
      GetOr(properties, AuthProperties::kSigV4SecretAccessKey, "");
  sigv4_config.session_token = GetOr(properties, AuthProperties::kSigV4SessionToken, "");

  const std::string provider_raw =
      GetOr(properties, AuthProperties::kSigV4CredentialsProvider, "");
  // Catch the common typo where a user sets one of the static-key pair but
  // not the other — without this check we'd silently fall through to the
  // default chain and the user would spend a while wondering why their
  // configured secret is being ignored.
  const bool has_ak = !sigv4_config.access_key_id.empty();
  const bool has_sk = !sigv4_config.secret_access_key.empty();
  if (provider_raw.empty() && has_ak != has_sk) {
    return InvalidArgument(
        "SigV4: access-key-id and secret-access-key must be set together");
  }
  ICEBERG_ASSIGN_OR_RAISE(sigv4_config.provider,
                          ResolveCredentialsProvider(provider_raw, has_ak));

  ICEBERG_ASSIGN_OR_RAISE(auto signer, SigV4Signer::Make(std::move(sigv4_config)));

  // Optional delegate auth type: the inner manager (e.g., OAuth2) produces a
  // session whose headers are then SigV4-signed on top. Matches the Java
  // RESTSigV4AuthManager behaviour.
  std::unique_ptr<AuthManager> delegate;
  auto delegate_it = properties.find(AuthProperties::kSigV4DelegateAuthType);
  if (delegate_it != properties.end() && !delegate_it->second.empty()) {
    // Avoid infinite recursion if a user sets the delegate type back to sigv4.
    if (delegate_it->second == AuthProperties::kAuthTypeSigV4) {
      return InvalidArgument(
          "SigV4 delegate auth type cannot itself be 'sigv4' (would recurse)");
    }
    // Build a properties map with rest.auth.type set to the delegate type, so
    // AuthManagers::Load resolves the inner manager.
    std::unordered_map<std::string, std::string> delegate_properties = properties;
    delegate_properties[AuthProperties::kAuthType] = delegate_it->second;
    ICEBERG_ASSIGN_OR_RAISE(delegate, AuthManagers::Load(name, delegate_properties));
  }

  return std::make_unique<SigV4Manager>(std::move(signer), std::move(delegate));
}

}  // namespace iceberg::rest::auth
