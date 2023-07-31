#ifndef ALIBABACLOUD_CREDENTIAL_RAMROLEARNPROVIDER_H_
#define ALIBABACLOUD_CREDENTIAL_RAMROLEARNPROVIDER_H_
#include <alibabacloud/credential/Config.hpp>
#include <alibabacloud/credential/Constant.hpp>
#include <alibabacloud/credential/provider/NeedFreshProvider.hpp>
#include <string>

namespace Alibabacloud {
namespace Credential {

class RamRoleArnProvider : public NeedFreshedProvider,
                           std::enable_shared_from_this<RamRoleArnProvider> {
public:
  RamRoleArnProvider(std::shared_ptr<Config> config,
                     const std::string regionId = "cn-hangzhou")
      : config_(config), regionId_(regionId) {
    credential_.setAccessKeyId(config_->accessKeyId())
        .setAccessKeySecret(config_->accessKeySecret())
        .setType(Constant::RAM_ROLE_ARN);
  }

  virtual ~RamRoleArnProvider() {}

protected:
  virtual bool refreshCredential() const override;

  std::shared_ptr<Config> config_ = nullptr;
  std::string regionId_;
};

} // namespace Credential

} // namespace Alibabacloud

#endif