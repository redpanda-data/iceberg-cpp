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

#include <gtest/gtest.h>

namespace iceberg::rest {

TEST(SslConfigFromPropertiesTest, DefaultsWhenAbsent) {
  const SslConfig ssl = SslConfigFromProperties({});
  EXPECT_TRUE(ssl.verify);
  EXPECT_TRUE(ssl.ca_info.empty());
  EXPECT_TRUE(ssl.ca_path.empty());
  EXPECT_TRUE(ssl.crl_file.empty());
}

TEST(SslConfigFromPropertiesTest, VerifyFalseDisablesVerification) {
  const SslConfig ssl = SslConfigFromProperties({{"ssl.verify", "false"}});
  EXPECT_FALSE(ssl.verify);
}

TEST(SslConfigFromPropertiesTest, VerifyNonFalseKeepsVerificationOn) {
  const SslConfig ssl = SslConfigFromProperties({{"ssl.verify", "true"}});
  EXPECT_TRUE(ssl.verify);
}

TEST(SslConfigFromPropertiesTest, PopulatesCaAndCrlPaths) {
  const SslConfig ssl = SslConfigFromProperties({
      {"ssl.ca-info", "/etc/ssl/ca.pem"},
      {"ssl.ca-path", "/etc/ssl/certs"},
      {"ssl.crl-file", "/etc/ssl/revoked.crl"},
  });
  EXPECT_EQ(ssl.ca_info, "/etc/ssl/ca.pem");
  EXPECT_EQ(ssl.ca_path, "/etc/ssl/certs");
  EXPECT_EQ(ssl.crl_file, "/etc/ssl/revoked.crl");
}

}  // namespace iceberg::rest
