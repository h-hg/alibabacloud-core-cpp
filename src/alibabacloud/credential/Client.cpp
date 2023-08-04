#include <alibabacloud/credential/Client.hpp>
#include <alibabacloud/credential/Config.hpp>
#include <alibabacloud/credential/Constant.hpp>
#include <alibabacloud/credential/Credential.hpp>
#include <alibabacloud/credential/provider/AccessKeyProvider.hpp>
#include <alibabacloud/credential/provider/BearerTokenProvider.hpp>
#include <alibabacloud/credential/provider/EcsRamRoleProvider.hpp>
#include <alibabacloud/credential/provider/RamRoleArnProvider.hpp>
#include <alibabacloud/credential/provider/RsaKeyPairProvider.hpp>
#include <alibabacloud/credential/provider/StsProvider.hpp>
#include <darabonba/Env.hpp>
#include <darabonba/Ini.hpp>
#include <fstream>

namespace Alibabacloud {
namespace Credential {

static std::shared_ptr<Provider> getProviderFromEnvVar() {
  std::string accessKeyId =
      Darabonba::Env::getEnv("ALIBABA_CLOUD_ACCESS_KEY_ID");
  std::string accessKeySecret =
      Darabonba::Env::getEnv("ALIBABA_CLOUD_ACCESS_KEY_SECRET");
  std::string securityToken =
      Darabonba::Env::getEnv("ALIBABA_CLOUD_SECURITY_TOKEN");
  if (accessKeyId.empty() || accessKeySecret.empty()) {
    return nullptr;
  }
  auto pConfig = std::make_shared<Config>();
  auto &config = *pConfig;
  config.setAccessKeyId(accessKeyId).setAccessKeySecret(accessKeySecret);
  if (securityToken.empty()) {
    return std::shared_ptr<Provider>(new AccessKeyProvider(pConfig));
  } else {
    config.setSecurityToken(securityToken);
    auto p = new StsProvider(pConfig);
    return std::shared_ptr<Provider>(p);
  }
  return nullptr;
}

static std::shared_ptr<Provider> getProviderFromProfile() {
  // TODO:
#ifdef _WIN32
  auto home = Darabonba::Env::get("USERPROFILE");
  char sep = '\\';
#else
  auto home = Darabonba::Env::getEnv("HOME");
  char sep = '/';
#endif
  if (home.back() != sep) {
    home.push_back(sep);
  }
  std::ifstream ifs(home + ".alibabacloud/credentials.ini");
  if (!ifs.good()) {
    return nullptr;
  }
  try {
    auto config = Darabonba::Ini::parse(ifs);
  } catch (Darabonba::Exception e) {
    return nullptr;
  }

  return nullptr;
}

std::shared_ptr<Provider> Client::makeProvider(std::shared_ptr<Config> config) {

  auto type = config->type();

  if (type.empty()) {
    // TODO:: use the default provider
    return nullptr;
  } else if (type == Constant::ACCESS_KEY) {
    auto p = new AccessKeyProvider(config);
    return std::shared_ptr<Provider>(p);
  } else if (type == Constant::BEARER) {
    auto p = new BearerTokenProvider(config);
    return std::shared_ptr<Provider>(p);
  } else if (type == Constant::STS) {
    auto p = new StsProvider(config);
    return std::shared_ptr<Provider>(p);
  } else if (type == Constant::ECS_RAM_ROLE) {
    auto p = new EcsRamRoleProvider(config);
    return std::shared_ptr<Provider>(p);
  } else if (type == Constant::RAM_ROLE_ARN) {
    auto p = new RamRoleArnProvider(config);
    return std::shared_ptr<Provider>(p);
  } else if (type == Constant::RSA_KEY_PAIR) {
    auto p = new RsaKeyPairProvider(config);
    return std::shared_ptr<Provider>(p);
  } else {
    // TODO:
    return nullptr;
    // getProvider
  }
  return nullptr;
}

} // namespace Credential
} // namespace Alibabacloud
