#ifndef ALIBABACLOUD_CREDENTIAL_RSAKEYPAIRPROVIDER_H_
#define ALIBABACLOUD_CREDENTIAL_RSAKEYPAIRPROVIDER_H_
#include <alibabacloud/credential/Config.hpp>
#include <alibabacloud/credential/Constant.hpp>
#include <alibabacloud/credential/provider/NeedFreshProvider.hpp>

#include <string>

namespace Alibabacloud {
namespace Credential {

class RsaKeyPairProvider : public NeedFreshedProvider,
                           std::enable_shared_from_this<RsaKeyPairProvider> {
public:
  RsaKeyPairProvider(std::shared_ptr<Config> config,
                     const std::string regionId = "cn-hangzhou")
      : config_(config), regionId_(regionId) {
    credential_.setAccessKeyId(config_->accessKeyId())
        .setAccessKeySecret(config_->accessKeySecret())
        .setType(Constant::RSA_KEY_PAIR);
  }
  //  RsaKeyPairProvider(const std::string &roleArn, const std::string
  //  &accessKeyId,
  //                     const std::string &accessKeySecret,
  //                     const std::string &regionId,
  //                     const std::string &roleSessionName,
  //                     const std::string &policy, int durationSeconds)
  //      : roleArn_(std::make_shared<std::string>(roleArn)),
  //        regionId_(std::make_shared<std::string>(regionId)),
  //        roleSessionName_(std::make_shared<std::string>(roleSessionName)),
  //        policy_(std::make_shared<std::string>(policy)),
  //        durationSeconds_(std::make_shared<int64_t>(durationSeconds)) {}
  //
  //  RsaKeyPairProvider(const Config &config)
  //      : roleArn_(config.hasRoleArn()
  //                     ? std::make_shared<std::string>(config.getRoleArn())
  //                     : nullptr),
  //        regionId_(std::make_shared<std::string>("cn-hangzhou")),
  //        roleSessionName_(
  //            config.hasRoleSessionName()
  //                ? std::make_shared<std::string>(config.getRoleSessionName())
  //                : nullptr),
  //        policy_(config.hasPolicy()
  //                    ? std::make_shared<std::string>(config.getPolicy())
  //                    : nullptr),
  //        durationSeconds_(
  //            config.hasDurationSeconds()
  //                ? std::make_shared<int64_t>(config.getDurationSeconds())
  //                : nullptr) {}

  virtual ~RsaKeyPairProvider() {}

  // virtual std::shared_ptr<CredentialBase> getCredential();

protected:
  virtual bool refreshCredential() const override;

  std::shared_ptr<Config> config_ = nullptr;
  std::string regionId_;

  // std::shared_ptr<std::string> roleArn_;
  // std::shared_ptr<std::string> accessKeyId_;
  // std::shared_ptr<std::string> accessKeySecret_;
  //  std::shared_ptr<std::string> regionId_;
  //  std::shared_ptr<std::string> roleSessionName_;
  //  std::shared_ptr<std::string> policy_;
  //  std::shared_ptr<int64_t> durationSeconds_;
};

} // namespace Credential

} // namespace Alibabacloud

#endif