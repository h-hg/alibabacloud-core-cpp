#ifndef ALIBABACLOUD_CREDENTIAL_CLIENT_H_
#define ALIBABACLOUD_CREDENTIAL_CLIENT_H_

#include <alibabacloud/credential/Config.hpp>
#include <alibabacloud/credential/CredentialBase.hpp>
#include <memory>
#include <string>

namespace Alibabacloud {
namespace Credential {
class Client {
public:
  explicit Client(std::shared_ptr<Config> config);
  ~Client() = default;

  std::string getAccessKeyId() { return credential_->getAccessKeyId(); }

  std::string getAccessKeySecret() { return credential_->getAccessKeySecret(); }

  std::string getSecurityToken() { return credential_->getSecurityToken(); }

  std::string getBearerToken() { return credential_->getBearerToken(); }

  std::string getType() { return credential_->getType(); }

private:
  std::shared_ptr<CredentialBase> credential_;
};

} // namespace Credential
} // namespace Alibabacloud

#endif