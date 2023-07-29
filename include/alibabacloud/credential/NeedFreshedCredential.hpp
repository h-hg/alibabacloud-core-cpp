#ifndef ALIBABACLOUD_CREDENTIAL_NEEDFRESHCREDENTIAL_H_
#define ALIBABACLOUD_CREDENTIAL_NEEDFRESHCREDENTIAL_H_
#include <alibabacloud/credential/CredentialBase.hpp>

#include <ctime>
namespace Alibabacloud {
namespace Credential {
class NeedFreshedCredential : public CredentialBase {
public:
  NeedFreshedCredential() = default;
  NeedFreshedCredential(long long expiration) : expiration_(expiration) {}
  virtual ~NeedFreshedCredential() {}

  virtual std::string getAccessKeyId() = 0;
  virtual std::string getAccessKeySecret() = 0;
  virtual std::string getSecurityToken() = 0;
  virtual std::string getBearerToken() = 0;
  virtual std::string getType() = 0;

protected:
  virtual bool needFresh() const {
    long long now = static_cast<long long>(time(nullptr));
    return expiration_ - now <= 180;
  }

  virtual void refreshCredential() = 0;
  virtual void refresh() {
    if (needFresh()) {
      refreshCredential();
    }
  }

  long long expiration_;
};
} // namespace Credential
} // namespace Alibabacloud

#endif