#ifndef ALIBABACLOUD_CREDENTIAL_RSAKEYPAIRCREDENTIAL_H_
#define ALIBABACLOUD_CREDENTIAL_RSAKEYPAIRCREDENTIAL_H_

#include <alibabacloud/credential/Constant.hpp>
#include <alibabacloud/credential/NeedFreshedCredential.hpp>
#include <alibabacloud/credential/provider/ProviderBase.hpp>
#include <memory>
#include <string>

namespace Alibabacloud {

namespace Credential {
class RsaKeyPairCredential : public NeedFreshedCredential {
public:
  RsaKeyPairCredential(const std::string &accessKeyId,
                       const std::string &accessKeySecret, long long expiration,
                       std::shared_ptr<ProviderBase> provider)
      : NeedFreshedCredential(expiration),
        accessKeyId_(std::make_shared<std::string>(accessKeyId)),
        accessKeySecret_(std::make_shared<std::string>(accessKeySecret)),
        provider_(provider) {}
  RsaKeyPairCredential(std::shared_ptr<std::string> accessKeyId,
                       std::shared_ptr<std::string> accessKeySecret,
                       long long expiration,
                       std::shared_ptr<ProviderBase> provider)
      : NeedFreshedCredential(expiration), accessKeyId_(accessKeyId),
        accessKeySecret_(accessKeySecret), provider_(provider) {}
  virtual ~RsaKeyPairCredential() {}

  virtual std::string getAccessKeyId() override {
    refreshCredential();
    return accessKeyId_ ? *accessKeyId_ : "";
  }
  virtual std::string getAccessKeySecret() override {
    refreshCredential();
    return accessKeySecret_ ? *accessKeySecret_ : "";
  }
  virtual std::string getSecurityToken() override { return ""; }
  virtual std::string getBearerToken() override { return ""; }
  virtual std::string getType() override { return Constant::RSA_KEY_PAIR; }

protected:
  virtual void refreshCredential() override {
    auto credential = provider_->getCredential();
    if (credential != nullptr) {
      *this = dynamic_cast<RsaKeyPairCredential &&>(*credential.get());
    }
  }

  std::shared_ptr<std::string> accessKeyId_;
  std::shared_ptr<std::string> accessKeySecret_;

  std::shared_ptr<ProviderBase> provider_;
};
} // namespace Credential

} // namespace Alibabacloud
#endif
