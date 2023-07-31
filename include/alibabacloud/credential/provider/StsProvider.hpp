#ifndef ALIBABACLOUD_Provider_STSProvider_H_
#define ALIBABACLOUD_Provider_STSProvider_H_

#include <alibabacloud/credential/Config.hpp>
#include <alibabacloud/credential/Constant.hpp>
#include <alibabacloud/credential/provider/Provider.hpp>
#include <memory>
#include <string>

namespace Alibabacloud {
namespace Credential {
class StsProvider : public Provider {
public:

  StsProvider(std::shared_ptr<Config> config) {
    credential_.setAccessKeyId(config->accessKeyId())
        .setAccessKeySecret(config->accessKeySecret())
        .setSecurityToken(config->securityToken())
        .setType(Constant::STS);
  }

  virtual ~StsProvider() {}

  virtual Credential &getCredential() override { return credential_; }
  virtual const Credential &getCredential() const override { return credential_; }

protected:

};
} // namespace Credential

} // namespace Alibabacloud
#endif