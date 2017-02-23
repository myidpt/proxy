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

#include "precompiled/precompiled.h"

#include "common/common/logger.h"
#include "envoy/network/connection.h"
#include "envoy/network/filter.h"
#include "envoy/server/instance.h"
#include "server/configuration_impl.h"
#include "src/envoy/auth/secure_naming_map.h"

namespace Network {
namespace Auth {

class Config : public Logger::Loggable<Logger::Id::http> {
 public:
  Config(const Json::Object& config, Server::Instance& server) {
    std::string map_path;
    if (config.hasObject("map_path")) {
      map_path = config.getString("map_path");
    } else {
      log().error("Error: map_path for secure naming is not specified: {}.",
                  __func__);
    }
    SecureNamingMap::createSecureNamingMap(map_path);
  }
};

typedef std::shared_ptr<Config> ConfigPtr;

// One per connection, to get the IP.
class Instance : public Network::ReadFilter {
 public:
  Instance(ConfigPtr config) : config_(config) {}

  Network::FilterStatus onData(Buffer::Instance& data) override {
    return Network::FilterStatus::Continue;
  }

  Network::FilterStatus onNewConnection() override {
    return Network::FilterStatus::Continue;
  }

  void initializeReadFilterCallbacks(
      Network::ReadFilterCallbacks& callbacks) override {
    read_callbacks_ = &callbacks;
  }

 private:
  ConfigPtr config_;
  Network::ReadFilterCallbacks* read_callbacks_{};
};

}  // namespace Auth
}  // namespace Network

namespace Server {
namespace Configuration {

class AuthConfig : public NetworkFilterConfigFactory {
 public:
  NetworkFilterFactoryCb tryCreateFilterFactory(
      NetworkFilterType type, const std::string& name,
      const Json::Object& config, Server::Instance& server) override {
    if (type != NetworkFilterType::Read || name != "auth_secure_naming") {
      return nullptr;
    }

    Network::Auth::ConfigPtr auth_config(
        new Network::Auth::Config(config, server));

    return [auth_config](Network::FilterManager& filter_manager) -> void {
      std::shared_ptr<Network::Auth::Instance> instance(
          new Network::Auth::Instance(auth_config));
      filter_manager.addReadFilter(Network::ReadFilterPtr(instance));
    };
  }
};

static RegisterNetworkFilterConfigFactory<AuthConfig> register_;

}  // namespace Configuration
}  // namespace server
