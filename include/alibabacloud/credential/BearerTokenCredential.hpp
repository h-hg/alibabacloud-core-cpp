#ifndef ALIBABACLOUD_CREDENTIAL_BEARERTOKENCREDENTIAL_H_
#define ALIBABACLOUD_CREDENTIAL_BEARERTOKENCREDENTIAL_H_

#include <alibabacloud/credential/Constant.hpp>
#include <alibabacloud/credential/CredentialBase.hpp>
#include <memory>
#include <string>

namespace Alibabacloud {
namespace Credential {
class BearerTokenCredential : public CredentialBase {
public:
  BearerTokenCredential(const std::string &bearerToken)
      : bearerToken_(std::make_shared<std::string>(bearerToken)) {}

  BearerTokenCredential(std::shared_ptr<std::string> bearToken)
      : bearerToken_(bearToken) {}

  virtual ~BearerTokenCredential() {}

  virtual std::string getAccessKeyId() override { return ""; }
  virtual std::string getAccessKeySecret() override { return ""; }
  virtual std::string getSecurityToken() override { return ""; }
  virtual std::string getBearerToken() override { return ""; }
  virtual std::string getType() override { return Constant::BEARER; }

protected:
  std::shared_ptr<std::string> bearerToken_;
};
} // namespace Credential

} // namespace Alibabacloud
#endif