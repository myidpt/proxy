/* Copyright 2016 Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include "precompiled/precompiled.h"

#include "common/common/logger.h"

namespace Network {
namespace Auth {

// The Istio mTLS Authentication secure naming part.
class SecureNamingMap final : public Logger::Loggable<Logger::Id::http> {
 public:
  // Reads the secure naming map from file and creates the singleton.
  static void createSecureNamingMap(const std::string& map_path);

  // Get the service accounts mapped from a service name.
  static std::list<std::string> const* getMappedServiceAccount(
      const std::string& serivce_name);

  // Print the secure naming map.
  void printMap() const;

 private:
  // The constructor.
  SecureNamingMap(const std::string& map_path);

  // The attributes read from the config file.
  std::map<std::string, std::string> config_attributes_;

  // Secure naming mapping from service name to service accounts.
  std::map<std::string, std::list<std::string>> map_;

  // Singleton.
  static std::unique_ptr<SecureNamingMap> instance_;
};

}  // namespace Auth
}  // namespace Network
