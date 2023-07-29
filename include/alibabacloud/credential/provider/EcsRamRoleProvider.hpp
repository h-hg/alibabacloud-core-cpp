#ifndef ALIBABACLOUD_CREDENTIAL_PROVIDER_PROVIDERBASE_H_
#define ALIBABACLOUD_CREDENTIAL_PROVIDER_PROVIDERBASE_H_
#include <alibabacloud/credential/Config.hpp>
#include <alibabacloud/credential/provider/ProviderBase.hpp>
#include <memory>
#include <string>

namespace Alibabacloud {
namespace Credential {

class EcsRamRoleProvider : public ProviderBase,
                           std::enable_shared_from_this<EcsRamRoleProvider> {
public:
  EcsRamRoleProvider(std::shared_ptr<std::string> roleName)
      : roleName_(roleName) {}

  EcsRamRoleProvider(const std::string &roleName)
      : roleName_(std::make_shared<std::string>(roleName)) {}
  EcsRamRoleProvider(const Config &config) : roleName_(config.roleName) {}

  virtual ~EcsRamRoleProvider() {}

  virtual std::shared_ptr<CredentialBase> getCredential();

protected:
  static const std::string URL_IN_ECS_META_DATA;
  static const std::string ECS_META_DATA_FETCH_ERROR_MSG;
  static const std::string META_DATA_SERVICE_HOST;

  std::shared_ptr<std::string> roleName_;

  static std::string getRoleName();
};

} // namespace Credential

} // namespace Alibabacloud
#endif