#ifndef ALIBABACLOUD_CREDENTIAL_CREDENTIALBASE_H_
#define ALIBABACLOUD_CREDENTIAL_CREDENTIALBASE_H_

#include <string>
namespace Alibabacloud {
namespace Credential {

class CredentialBase {
public:
  virtual std::string getAccessKeyId() = 0;
  virtual std::string getAccessKeySecret() = 0;
  virtual std::string getSecurityToken() = 0;
  virtual std::string getBearerToken() = 0;
  virtual std::string getType() = 0;
  virtual ~CredentialBase() {}
};

} // namespace Credential
} // namespace Alibabacloud
#endif