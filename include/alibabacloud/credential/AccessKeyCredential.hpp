#ifndef ALIBABACLOUD_CREDENTIAL_ACCESSKEYCREDENTIAL_H_
#define ALIBABACLOUD_CREDENTIAL_ACCESSKEYCREDENTIAL_H_

#include <alibabacloud/credential/Constant.hpp>
#include <alibabacloud/credential/CredentialBase.hpp>
#include <memory>
#include <string>

namespace Alibabacloud {
namespace Credential {
class AccessKeyCredential : public CredentialBase {
public:
  AccessKeyCredential(const std::string &accessKeyId,
                      const std::string &accessKeySecret)
      : accessKeyId_(std::make_shared<std::string>(accessKeyId)),
        accessKeySecret_(std::make_shared<std::string>(accessKeySecret)) {}

  AccessKeyCredential(std::shared_ptr<std::string> accessKeyId,
                      std::shared_ptr<std::string> accessKeySecret)
      : accessKeyId_(accessKeyId), accessKeySecret_(accessKeySecret) {}

  virtual ~AccessKeyCredential() {}

  virtual std::string getAccessKeyId() override {
    return accessKeyId_ ? *accessKeyId_ : "";
  }
  virtual std::string getAccessKeySecret() override {
    return accessKeySecret_ ? *accessKeySecret_ : "";
  }
  virtual std::string getSecurityToken() override { return ""; }
  virtual std::string getBearerToken() override { return ""; }
  virtual std::string getType() override { return Constant::ACCESS_KEY; }

protected:
  std::shared_ptr<std::string> accessKeyId_;
  std::shared_ptr<std::string> accessKeySecret_;
};
} // namespace Credential

} // namespace Alibabacloud
#endif