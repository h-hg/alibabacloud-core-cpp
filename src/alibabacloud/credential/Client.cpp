#include <alibabacloud/credential/AccessKeyCredential.hpp>
#include <alibabacloud/credential/BearerTokenCredential.hpp>
#include <alibabacloud/credential/Client.hpp>
#include <alibabacloud/credential/Config.hpp>
#include <alibabacloud/credential/Constant.hpp>
#include <alibabacloud/credential/EcsRamRoleCredential.hpp>
#include <alibabacloud/credential/RamRoleArnCredential.hpp>
#include <alibabacloud/credential/RsaKeyPairCredential.hpp>
#include <alibabacloud/credential/StsCredential.hpp>
#include <alibabacloud/credential/provider/EcsRamRoleProvider.hpp>
#include <alibabacloud/credential/provider/RamRoleArnProvider.hpp>
#include <alibabacloud/credential/provider/RsaKeyPairProvider.hpp>

namespace Alibabacloud {
namespace Credential {
Client::Client(std::shared_ptr<Config> config) {

  if (!config || !config->type) {
    // todo: use the default provider
  } else if (*config->type == Constant::ACCESS_KEY) {
    credential_ = std::make_shared<AccessKeyCredential>(
        config->accessKeyId, config->accessKeySecret);
  } else if (*config->type == Constant::BEARER) {
    credential_ = std::make_shared<BearerTokenCredential>(config->bearerToken);
  } else if (*config->type == Constant::STS) {
    credential_ = std::make_shared<StsCredential>(
        config->accessKeyId, config->accessKeySecret, config->securityToken);
  } else if (*config->type == Constant::ECS_RAM_ROLE) {
    auto provider = std::make_shared<EcsRamRoleProvider>(*config);
    credential_ = provider->getCredential();
  } else if (*config->type == Constant::RAM_ROLE_ARN) {
    auto provider = std::make_shared<RamRoleArnProvider>(*config);
    credential_ = provider->getCredential();
  } else if (*config->type == Constant::RSA_KEY_PAIR) {
    auto provider = std::make_shared<RsaKeyPairProvider>(*config);
    credential_ = provider->getCredential();
  } else {
    // getProvider
  }
}

} // namespace Credential
} // namespace Alibabacloud
