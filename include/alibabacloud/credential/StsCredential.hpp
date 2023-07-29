#ifndef ALIBABACLOUD_CREDENTIAL_STSCREDENTIAL_H_
#define ALIBABACLOUD_CREDENTIAL_STSCREDENTIAL_H_

#include <alibabacloud/credential/Constant.hpp>
#include <alibabacloud/credential/CredentialBase.hpp>
#include <memory>
#include <string>

namespace Alibabacloud {
namespace Credential {
class StsCredential : public CredentialBase {
public:
  StsCredential(const std::string &accessKeyId,
                const std::string &accessKeySecret,
                const std::string &securityToken)
      : accessKeyId_(std::make_shared<std::string>(accessKeyId)),
        accessKeySecret_(std::make_shared<std::string>(accessKeySecret)),
        securityToken_(std::make_shared<std::string>(securityToken)) {}
  StsCredential(std::shared_ptr<std::string> accessKeyId,
                std::shared_ptr<std::string> accessKeySecret,
                std::shared_ptr<std::string> securityToken)
      : accessKeyId_(accessKeyId), accessKeySecret_(accessKeySecret),
        securityToken_(securityToken) {}
  virtual ~StsCredential() {}

  virtual std::string getAccessKeyId() override {
    return accessKeyId_ ? *accessKeyId_ : "";
  }
  virtual std::string getAccessKeySecret() override {
    return accessKeySecret_ ? *accessKeySecret_ : "";
  }
  virtual std::string getSecurityToken() override {
    return securityToken_ ? *securityToken_ : "";
  }

  virtual std::string getBearerToken() override { return ""; }
  virtual std::string getType() override { return Constant::STS; }

protected:
  std::shared_ptr<std::string> accessKeyId_;
  std::shared_ptr<std::string> accessKeySecret_;
  std::shared_ptr<std::string> securityToken_;
};
} // namespace Credential

} // namespace Alibabacloud
#endif