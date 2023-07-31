#ifndef ALIBABACLOUD_PROVIDER_ACCESSKEYPROVIDER_H_
#define ALIBABACLOUD_PROVIDER_ACCESSKEYPROVIDER_H_

#include <alibabacloud/credential/Config.hpp>
#include <alibabacloud/credential/Constant.hpp>
#include <alibabacloud/credential/Credential.hpp>
#include <alibabacloud/credential/provider/Provider.hpp>
#include <memory>
#include <string>

namespace Alibabacloud {
namespace Credential {

class AccessKeyProvider : public Provider {
public:
  AccessKeyProvider(std::shared_ptr<Config> config) {
    credential_.setAccessKeyId(config->accessKeyId())
        .setAccessKeySecret(config->accessKeySecret())
        .setType(Constant::ACCESS_KEY);
  }
  virtual ~AccessKeyProvider() {}

  virtual Credential &getCredential() override { return credential_; }
  virtual const Credential &getCredential() const override {
    return credential_;
  }
};
} // namespace Credential

} // namespace Alibabacloud
#endif