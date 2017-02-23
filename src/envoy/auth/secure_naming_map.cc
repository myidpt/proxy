/*
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

#include "src/envoy/auth/secure_naming_map.h"
#include "common/common/logger.h"
#include "common/common/utility.h"
#include "rapidjson/document.h"
#include "rapidjson/error/en.h"
#include "rapidjson/istreamwrapper.h"

namespace Network {
namespace Auth {
namespace {

static spdlog::logger& Log() {
  static spdlog::logger& instance =
      Logger::Registry::getLog(Logger::Id::config);
  return instance;
}

}  // namespace

std::unique_ptr<SecureNamingMap> SecureNamingMap::instance_;

void SecureNamingMap::createSecureNamingMap(const std::string& map_path) {
  if (instance_ == nullptr) {
    instance_.reset(new SecureNamingMap(map_path));
  }
}

std::list<std::string> const* SecureNamingMap::getMappedServiceAccount(
    const std::string& service_name) {
  auto it = instance_->map_.find(service_name);
  if (it == instance_->map_.end()) {
    return nullptr;
  } else {
    return &(it->second);
  }
}

SecureNamingMap::SecureNamingMap(const std::string& map_path) {
  rapidjson::Document document;
  std::ifstream file_stream(map_path);
  rapidjson::IStreamWrapper stream_wrapper(file_stream);
  if (document.ParseStream(stream_wrapper).HasParseError()) {
    Log().error(fmt::format("Secure naming file loading error(offset {}): {}\n",
                            document.GetErrorOffset(),
                            GetParseError_En(document.GetParseError())));
    return;
  }

  for (auto it = document.MemberBegin(); it != document.MemberEnd(); ++it) {
    std::list<std::string> service_accounts;
    if (it->value.IsArray()) {
      for (rapidjson::SizeType i = 0; i < it->value.Size(); i++) {
        if (it->value[i].IsString()) {
          service_accounts.push_back(it->value[i].GetString());
        } else {
          Log().error("Seucre naming file loading format error.");
        }
      }
    } else {
      if (it->value.IsString()) {
        service_accounts.push_back(it->value.GetString());
      } else {
        Log().error("Seucre naming file loading format error.");
      }
    }
    if (!service_accounts.empty()) {
      map_[it->name.GetString()] = service_accounts;
    }
  }

  printMap();
}

void SecureNamingMap::printMap() const {
  Log().debug("Print secure naming map.\n");
  for (auto mapping : map_) {
    Log().debug("{}:", mapping.first);
    for (std::string service_account : mapping.second) {
      Log().debug("  {}", service_account);
    }
  }
}

}  // namespace Auth
}  // namespace Network
