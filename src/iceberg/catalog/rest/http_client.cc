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

#include "iceberg/catalog/rest/http_client.h"

#include <cpr/cpr.h>
#include <nlohmann/json.hpp>

#include "iceberg/catalog/rest/auth/auth_session.h"
#include "iceberg/catalog/rest/constant.h"
#include "iceberg/catalog/rest/error_handlers.h"
#include "iceberg/catalog/rest/json_serde_internal.h"
#include "iceberg/catalog/rest/rest_util.h"
#include "iceberg/json_serde_internal.h"
#include "iceberg/result.h"
#include "iceberg/util/macros.h"
#include "iceberg/util/url_encoder.h"

namespace iceberg::rest {

class HttpResponse::Impl {
 public:
  explicit Impl(cpr::Response&& response) : response_(std::move(response)) {}
  ~Impl() = default;

  int32_t status_code() const { return static_cast<int32_t>(response_.status_code); }

  std::string body() const { return response_.text; }

  std::unordered_map<std::string, std::string> headers() const {
    return {response_.header.begin(), response_.header.end()};
  }

 private:
  cpr::Response response_;
};

HttpResponse::HttpResponse() = default;
HttpResponse::~HttpResponse() = default;
HttpResponse::HttpResponse(HttpResponse&&) noexcept = default;
HttpResponse& HttpResponse::operator=(HttpResponse&&) noexcept = default;

int32_t HttpResponse::status_code() const { return impl_->status_code(); }

std::string HttpResponse::body() const { return impl_->body(); }

std::unordered_map<std::string, std::string> HttpResponse::headers() const {
  return impl_->headers();
}

namespace {

/// \brief Default error type for unparseable REST responses.
constexpr std::string_view kRestExceptionType = "RESTException";

/// \brief Prepare headers for an HTTP request.
///
/// Merges default + per-request headers and then lets the AuthSession
/// authenticate the request. The full request context (method, URL, query
/// params, body) is forwarded to the session so auth schemes that need to
/// sign over the request (e.g., SigV4) see what they need; header-only
/// schemes ignore the extra context.
Result<cpr::Header> BuildHeaders(
    std::string_view method, std::string_view url,
    const std::unordered_map<std::string, std::string>* query_params,
    std::string_view body,
    const std::unordered_map<std::string, std::string>& request_headers,
    const std::unordered_map<std::string, std::string>& default_headers,
    auth::AuthSession& session) {
  std::unordered_map<std::string, std::string> headers(default_headers);
  for (const auto& [key, val] : request_headers) {
    headers.insert_or_assign(key, val);
  }
  auth::SignableRequest signable{.method = method,
                                 .url = url,
                                 .query_params = query_params,
                                 .body = body};
  ICEBERG_RETURN_UNEXPECTED(session.Authenticate(signable, headers));
  return cpr::Header(headers.begin(), headers.end());
}

/// \brief Serialize a form-data map to an application/x-www-form-urlencoded
///        body string. Used so that SigV4 can hash the payload it will
///        actually see on the wire.
std::string EncodeFormBody(const std::unordered_map<std::string, std::string>& form_data) {
  std::string out;
  bool first = true;
  for (const auto& [key, val] : form_data) {
    if (!first) {
      out.push_back('&');
    }
    first = false;
    out.append(UrlEncoder::Encode(key));
    out.push_back('=');
    out.append(UrlEncoder::Encode(val));
  }
  return out;
}

cpr::SslOptions BuildSslOptions(const SslConfig& config) {
  cpr::SslOptions opts;
  opts.verify_host = config.verify;
  opts.verify_peer = config.verify;
  if (!config.ca_info.empty()) {
    opts.ca_info = config.ca_info;
  }
  if (!config.ca_path.empty()) {
    opts.ca_path = config.ca_path;
  }
  if (!config.crl_file.empty()) {
    opts.crl_file = config.crl_file;
  }
  return opts;
}

/// \brief Converts a map of string key-value pairs to cpr::Parameters.
cpr::Parameters GetParameters(
    const std::unordered_map<std::string, std::string>& params) {
  cpr::Parameters cpr_params;
  for (const auto& [key, val] : params) {
    cpr_params.Add({key, val});
  }
  return cpr_params;
}

/// \brief Checks if the HTTP status code indicates a successful response.
bool IsSuccessful(int32_t status_code) {
  return status_code == 200      // OK
         || status_code == 202   // Accepted
         || status_code == 204   // No Content
         || status_code == 304;  // Not Modified
}

/// \brief Builds a default ErrorResponse when the response body cannot be parsed.
ErrorResponse BuildDefaultErrorResponse(const cpr::Response& response) {
  std::string message;
  if (response.error) {
    message = response.error.message;
  } else if (!response.reason.empty()) {
    message = response.reason;
  } else {
    message = GetStandardReasonPhrase(response.status_code);
  }
  return {
      .code = static_cast<uint32_t>(response.status_code),
      .type = std::string(kRestExceptionType),
      .message = std::move(message),
  };
}

/// \brief Tries to parse the response body as an ErrorResponse.
Result<ErrorResponse> TryParseErrorResponse(const std::string& text) {
  if (text.empty()) {
    return InvalidArgument("Empty response body");
  }
  ICEBERG_ASSIGN_OR_RAISE(auto json_result, FromJsonString(text));
  ICEBERG_ASSIGN_OR_RAISE(auto error_result, ErrorResponseFromJson(json_result));
  return error_result;
}

/// \brief Handles failure responses by invoking the provided error handler.
Status HandleFailureResponse(const cpr::Response& response,
                             const ErrorHandler& error_handler) {
  if (IsSuccessful(response.status_code)) {
    return {};
  }
  auto parse_result = TryParseErrorResponse(response.text);
  const ErrorResponse final_error =
      parse_result.value_or(BuildDefaultErrorResponse(response));
  return error_handler.Accept(final_error);
}

}  // namespace

HttpClient::HttpClient(std::unordered_map<std::string, std::string> default_headers,
                       SslConfig ssl_config)
    : default_headers_{std::move(default_headers)},
      ssl_config_{std::move(ssl_config)},
      connection_pool_{std::make_unique<cpr::ConnectionPool>()} {
  // Set default Content-Type for all requests (including GET/HEAD/DELETE).
  // Many systems require that content type is set regardless and will fail,
  // even on an empty bodied request.
  default_headers_[kHeaderContentType] = kMimeTypeApplicationJson;
  default_headers_[kHeaderUserAgent] = kUserAgent;
}

HttpClient::~HttpClient() = default;

Result<HttpResponse> HttpClient::Get(
    const std::string& path, const std::unordered_map<std::string, std::string>& params,
    const std::unordered_map<std::string, std::string>& headers,
    const ErrorHandler& error_handler, auth::AuthSession& session) {
  ICEBERG_ASSIGN_OR_RAISE(
      auto all_headers,
      BuildHeaders("GET", path, &params, /*body=*/{}, headers, default_headers_, session));
  cpr::Response response = cpr::Get(cpr::Url{path}, GetParameters(params), all_headers,
                                    BuildSslOptions(ssl_config_), *connection_pool_);

  ICEBERG_RETURN_UNEXPECTED(HandleFailureResponse(response, error_handler));
  HttpResponse http_response;
  http_response.impl_ = std::make_unique<HttpResponse::Impl>(std::move(response));
  return http_response;
}

Result<HttpResponse> HttpClient::Post(
    const std::string& path, const std::string& body,
    const std::unordered_map<std::string, std::string>& headers,
    const ErrorHandler& error_handler, auth::AuthSession& session) {
  ICEBERG_ASSIGN_OR_RAISE(auto all_headers,
                          BuildHeaders("POST", path, /*query_params=*/nullptr, body,
                                       headers, default_headers_, session));
  cpr::Response response = cpr::Post(cpr::Url{path}, cpr::Body{body}, all_headers,
                                     BuildSslOptions(ssl_config_), *connection_pool_);

  ICEBERG_RETURN_UNEXPECTED(HandleFailureResponse(response, error_handler));
  HttpResponse http_response;
  http_response.impl_ = std::make_unique<HttpResponse::Impl>(std::move(response));
  return http_response;
}

Result<HttpResponse> HttpClient::PostForm(
    const std::string& path,
    const std::unordered_map<std::string, std::string>& form_data,
    const std::unordered_map<std::string, std::string>& headers,
    const ErrorHandler& error_handler, auth::AuthSession& session) {
  std::unordered_map<std::string, std::string> form_headers(headers);
  form_headers.insert_or_assign(kHeaderContentType, kMimeTypeFormUrlEncoded);
  // Encode the form body ourselves so that the same bytes we'll send on the
  // wire are available to sign (SigV4 hashes the payload).
  std::string form_body = EncodeFormBody(form_data);
  ICEBERG_ASSIGN_OR_RAISE(auto all_headers,
                          BuildHeaders("POST", path, /*query_params=*/nullptr, form_body,
                                       form_headers, default_headers_, session));
  std::vector<cpr::Pair> pair_list;
  pair_list.reserve(form_data.size());
  for (const auto& [key, val] : form_data) {
    pair_list.emplace_back(key, val);
  }
  cpr::Response response =
      cpr::Post(cpr::Url{path}, cpr::Payload(pair_list.begin(), pair_list.end()),
                all_headers, BuildSslOptions(ssl_config_), *connection_pool_);

  ICEBERG_RETURN_UNEXPECTED(HandleFailureResponse(response, error_handler));
  HttpResponse http_response;
  http_response.impl_ = std::make_unique<HttpResponse::Impl>(std::move(response));
  return http_response;
}

Result<HttpResponse> HttpClient::Head(
    const std::string& path, const std::unordered_map<std::string, std::string>& headers,
    const ErrorHandler& error_handler, auth::AuthSession& session) {
  ICEBERG_ASSIGN_OR_RAISE(auto all_headers,
                          BuildHeaders("HEAD", path, /*query_params=*/nullptr, /*body=*/{},
                                       headers, default_headers_, session));
  cpr::Response response = cpr::Head(cpr::Url{path}, all_headers,
                                     BuildSslOptions(ssl_config_), *connection_pool_);

  ICEBERG_RETURN_UNEXPECTED(HandleFailureResponse(response, error_handler));
  HttpResponse http_response;
  http_response.impl_ = std::make_unique<HttpResponse::Impl>(std::move(response));
  return http_response;
}

Result<HttpResponse> HttpClient::Delete(
    const std::string& path, const std::unordered_map<std::string, std::string>& params,
    const std::unordered_map<std::string, std::string>& headers,
    const ErrorHandler& error_handler, auth::AuthSession& session) {
  ICEBERG_ASSIGN_OR_RAISE(
      auto all_headers,
      BuildHeaders("DELETE", path, &params, /*body=*/{}, headers, default_headers_,
                   session));
  cpr::Response response = cpr::Delete(cpr::Url{path}, GetParameters(params), all_headers,
                                       BuildSslOptions(ssl_config_), *connection_pool_);

  ICEBERG_RETURN_UNEXPECTED(HandleFailureResponse(response, error_handler));
  HttpResponse http_response;
  http_response.impl_ = std::make_unique<HttpResponse::Impl>(std::move(response));
  return http_response;
}

}  // namespace iceberg::rest
