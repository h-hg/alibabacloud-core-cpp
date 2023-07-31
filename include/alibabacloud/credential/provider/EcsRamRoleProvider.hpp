#ifndef ALIBABACLOUD_CREDENTIAL_PROVIDER_PROVIDERBASE_H_
#define ALIBABACLOUD_CREDENTIAL_PROVIDER_PROVIDERBASE_H_
#include <alibabacloud/credential/Config.hpp>
#include <alibabacloud/credential/Constant.hpp>
#include <alibabacloud/credential/provider/NeedFreshProvider.hpp>
#include <alibabacloud/credential/provider/Provider.hpp>
#include <memory>
#include <string>

namespace Alibabacloud {
namespace Credential {

class EcsRamRoleProvider : public NeedFreshedProvider,
                           std::enable_shared_from_this<EcsRamRoleProvider> {
public:
  EcsRamRoleProvider(std::shared_ptr<Config> config) : config_(config) {}

  virtual ~EcsRamRoleProvider() {}

protected:
  virtual bool refreshCredential() const override;
  static std::string getRoleName();

  static const std::string URL_IN_ECS_META_DATA;
  static const std::string ECS_META_DATA_FETCH_ERROR_MSG;
  static const std::string META_DATA_SERVICE_HOST;

  // mutable std::shared_ptr<std::string> roleName_;
  std::shared_ptr<Config> config_ = nullptr;
};

} // namespace Credential

} // namespace Alibabacloud
#endif