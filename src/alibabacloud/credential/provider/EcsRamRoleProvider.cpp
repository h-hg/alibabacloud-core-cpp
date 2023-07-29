#include <alibabacloud/credential/EcsRamRoleCredential.hpp>
#include <alibabacloud/credential/provider/EcsRamRoleProvider.hpp>
#include <darabonba/Core.hpp>
#include <darabonba/Util.hpp>
#include <memory>

namespace Alibabacloud {
namespace Credential {

const std::string EcsRamRoleProvider::URL_IN_ECS_META_DATA =
    "/latest/meta-data/ram/security-credentials/";
const std::string EcsRamRoleProvider::ECS_META_DATA_FETCH_ERROR_MSG =
    "Failed to get RAM session credentials from ECS metadata service.";
const std::string EcsRamRoleProvider::META_DATA_SERVICE_HOST =
    "100.100.100.200";

std::shared_ptr<CredentialBase> EcsRamRoleProvider::getCredential() {
  if (roleName_ == nullptr) {
    roleName_ = std::make_shared<std::string>(getRoleName());
  }
  std::string roleName = roleName_ ? *roleName_ : "";
  std::string url =
      "https://" + META_DATA_SERVICE_HOST + URL_IN_ECS_META_DATA + roleName;
  Darabonba::Http::Request req(url);
  auto future = Darabonba::Core::doAction(req);
  auto resp = future.get();
  if (resp->statusCode() == 200) {
    auto result = Darabonba::Util::readAsJSON(resp->body());
    if (result["Code"].get<std::string>() == "Success") {
      std::string accessKeyId = result["AccessKeyId"].get<std::string>(),
                  accessKeySecret =
                      result["AccessKeySecret"].get<std::string>(),
                  securityToken = result["SecurityToken"].get<std::string>();
      auto expiration = strtotime(result["Expiration"].get<std::string>());
      return std::shared_ptr<CredentialBase>(
          new EcsRamRoleCredential(accessKeyId, accessKeySecret, securityToken,
                                   expiration, shared_from_this()));
    }
  }
  return nullptr;
}

std::string EcsRamRoleProvider::getRoleName() {
  std::string url = "https://" + META_DATA_SERVICE_HOST + URL_IN_ECS_META_DATA;
  Darabonba::Http::Request req(url);
  auto future = Darabonba::Core::doAction(req);
  auto resp = future.get();
  if (resp->statusCode() == 200) {
    return Darabonba::Util::readAsString(resp->body());
  }
  return "";
}

} // namespace Credential
} // namespace Alibabacloud