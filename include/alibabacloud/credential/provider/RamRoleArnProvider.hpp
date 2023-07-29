#ifndef ALIBABACLOUD_CREDENTIAL_RAMROLEARNPROVIDER_H_
#define ALIBABACLOUD_CREDENTIAL_RAMROLEARNPROVIDER_H_
#include <alibabacloud/credential/Config.hpp>
#include <alibabacloud/credential/provider/ProviderBase.hpp>
#include <string>

namespace Alibabacloud {
namespace Credential {

class RamRoleArnProvider : public ProviderBase,
                           std::enable_shared_from_this<RamRoleArnProvider> {
public:
  RamRoleArnProvider(std::shared_ptr<std::string> roleArn,
                     std::shared_ptr<std::string> accessKeyId,
                     std::shared_ptr<std::string> accessKeySecret,
                     std::shared_ptr<std::string> regionId,
                     std::shared_ptr<std::string> roleSessionName,
                     std::shared_ptr<std::string> policy,
                     std::shared_ptr<int> durationSeconds)
      : roleArn_(roleArn), accessKeyId_(accessKeyId),
        accessKeySecret_(accessKeySecret), regionId_(regionId),
        roleSessionName_(roleSessionName), policy_(policy),
        durationSeconds_(durationSeconds) {}

  RamRoleArnProvider(const std::string &roleArn, const std::string &accessKeyId,
                     const std::string &accessKeySecret,
                     const std::string &regionId,
                     const std::string &roleSessionName,
                     const std::string &policy, int durationSeconds)
      : roleArn_(std::make_shared<std::string>(roleArn)),
        accessKeyId_(std::make_shared<std::string>(accessKeyId)),
        accessKeySecret_(std::make_shared<std::string>(accessKeySecret)),
        regionId_(std::make_shared<std::string>(regionId)),
        roleSessionName_(std::make_shared<std::string>(roleSessionName)),
        policy_(std::make_shared<std::string>(policy)),
        durationSeconds_(std::make_shared<int>(durationSeconds)) {}

  RamRoleArnProvider(const Config &config)
      : roleArn_(config.roleArn), accessKeyId_(config.accessKeyId),
        accessKeySecret_(config.accessKeySecret),
        regionId_(std::make_shared<std::string>("cn-hangzhou")),
        roleSessionName_(config.roleSessionName), policy_(config.policy),
        durationSeconds_(config.durationSeconds) {}
  virtual ~RamRoleArnProvider() {}

  virtual std::shared_ptr<CredentialBase> getCredential();

protected:
  std::shared_ptr<std::string> roleArn_;
  std::shared_ptr<std::string> accessKeyId_;
  std::shared_ptr<std::string> accessKeySecret_;
  std::shared_ptr<std::string> regionId_;
  std::shared_ptr<std::string> roleSessionName_;
  std::shared_ptr<std::string> policy_;
  std::shared_ptr<int> durationSeconds_;
};

} // namespace Credential

} // namespace Alibabacloud

#endif