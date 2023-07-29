#ifndef ALIBABACLOUD_CREDENTIAL_DEFAULTPROVIDER_H_
#define ALIBABACLOUD_CREDENTIAL_DEFAULTPROVIDER_H_

#include <alibabacloud/credential/CredentialBase.hpp>
#include <alibabacloud/credential/provider/ProviderBase.hpp>
#include <memory>
#include <string>

namespace Alibabacloud {
namespace Credential {
class DefaultProvider : public ProviderBase {
public:
  virtual ~DefaultProvider() {}

protected:
};
} // namespace Credential

} // namespace Alibabacloud
#endif