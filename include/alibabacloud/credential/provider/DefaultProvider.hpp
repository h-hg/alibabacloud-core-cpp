#ifndef ALIBABACLOUD_CREDENTIAL_DEFAULTPROVIDER_H_
#define ALIBABACLOUD_CREDENTIAL_DEFAULTPROVIDER_H_

#include <alibabacloud/credential/Credential.hpp>
#include <alibabacloud/credential/provider/Provider.hpp>
#include <memory>
#include <string>

namespace Alibabacloud {
namespace Credential {
class DefaultProvider : public Provider {
public:
  virtual ~DefaultProvider() {}

protected:
};
} // namespace Credential

} // namespace Alibabacloud
#endif