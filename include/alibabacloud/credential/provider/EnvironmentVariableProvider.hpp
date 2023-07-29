#ifndef ALIBABACLOUD_CREDENTIAL_ENVIRONMENTVARIABLEPROVIDER_H_
#define ALIBABACLOUD_CREDENTIAL_ENVIRONMENTVARIABLEPROVIDER_H_

#include <alibabacloud/credential/AccessKeyCredential.hpp>
#include <alibabacloud/credential/CredentialBase.hpp>
#include <alibabacloud/credential/Exception.hpp>
#include <alibabacloud/credential/StsCredential.hpp>
#include <alibabacloud/credential/provider/ProviderBase.hpp>

#include <darabonba/Env.hpp>
#include <memory>

namespace Alibabacloud {
namespace Credential {
class EnvironmentVariableProvider : public ProviderBase {
public:
  virtual ~EnvironmentVariableProvider() {}

  virtual std::shared_ptr<CredentialBase> getCredential() {
    std::string accessKeyId =
        Darabonba::Env::getEnv("ALIBABA_CLOUD_ACCESS_KEY_ID");
    std::string accessKeySecret =
        Darabonba::Env::getEnv("ALIBABA_CLOUD_ACCESS_KEY_SECRET");
    std::string securityToken =
        Darabonba::Env::getEnv("ALIBABA_CLOUD_SECURITY_TOKEN");
    if (accessKeyId.empty() || accessKeySecret.empty()) {
      return nullptr;
    } else if (accessKeyId.empty()) {
      throw new CredentialException(
          "Environment variable accessKeyId cannot be empty");
    } else if (accessKeySecret.empty()) {
      throw new CredentialException(
          "Environment variable accessKeySecret cannot be empty");
    }
    if (securityToken.empty()) {
      return std::shared_ptr<CredentialBase>(
          new AccessKeyCredential(accessKeyId, accessKeySecret));
    } else {
      return std::shared_ptr<CredentialBase>(
          new StsCredential(accessKeyId, accessKeySecret, securityToken));
    }
  }

protected:
};
} // namespace Credential

} // namespace Alibabacloud
#endif