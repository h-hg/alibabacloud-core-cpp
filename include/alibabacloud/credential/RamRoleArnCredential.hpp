#ifndef ALIBABACLOUD_CREDENTIAL_RAMROLEARNCREDENTIAL_H_
#define ALIBABACLOUD_CREDENTIAL_RAMROLEARNCREDENTIAL_H_

#include <alibabacloud/credential/Constant.hpp>
#include <alibabacloud/credential/NeedFreshedCredential.hpp>
#include <alibabacloud/credential/provider/ProviderBase.hpp>
#include <memory>
#include <string>

namespace Alibabacloud {

namespace Credential {
class RamRoleArnCredential : public NeedFreshedCredential {
public:
  RamRoleArnCredential(const std::string &accessKeyId,
                       const std::string &accessKeySecret,
                       const std::string &securityToken, long long expiration,
                       std::shared_ptr<ProviderBase> provider)
      : NeedFreshedCredential(expiration),
        accessKeyId_(std::make_shared<std::string>(accessKeyId)),
        accessKeySecret_(std::make_shared<std::string>(accessKeySecret)),
        securityToken_(std::make_shared<std::string>(securityToken)),
        provider_(provider) {}
  RamRoleArnCredential(std::shared_ptr<std::string> accessKeyId,
                       std::shared_ptr<std::string> accessKeySecret,
                       std::shared_ptr<std::string> securityToken,
                       long long expiration,
                       std::shared_ptr<ProviderBase> provider)
      : NeedFreshedCredential(expiration), accessKeyId_(accessKeyId),
        accessKeySecret_(accessKeySecret), securityToken_(securityToken),
        provider_(provider) {}
  virtual ~RamRoleArnCredential() {}

  virtual std::string getAccessKeyId() override {
    refreshCredential();
    return accessKeyId_ ? *accessKeyId_ : "";
  }
  virtual std::string getAccessKeySecret() override {
    refreshCredential();
    return accessKeySecret_ ? *accessKeySecret_ : "";
  }
  virtual std::string getSecurityToken() override {
    refreshCredential();
    return securityToken_ ? *securityToken_ : "";
  }

  virtual std::string getBearerToken() override { return ""; }

  virtual std::string getType() override { return Constant::RAM_ROLE_ARN; }

protected:
  virtual void refreshCredential() override {
    auto credential = provider_->getCredential();
    if (credential != nullptr) {
      *this = dynamic_cast<RamRoleArnCredential &&>(*credential.get());
    }
  }

  std::shared_ptr<std::string> accessKeyId_;
  std::shared_ptr<std::string> accessKeySecret_;
  std::shared_ptr<std::string> securityToken_;

  std::shared_ptr<ProviderBase> provider_;
};
} // namespace Credential

} // namespace Alibabacloud
#endif
