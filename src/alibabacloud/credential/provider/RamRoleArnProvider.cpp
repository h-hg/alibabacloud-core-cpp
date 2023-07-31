#include <alibabacloud/credential/provider/RamRoleArnProvider.hpp>
#include <cstdint>
#include <darabonba/Core.hpp>
#include <darabonba/Util.hpp>
#include <darabonba/http/Query.hpp>
#include <darabonba/http/URL.hpp>
#include <darabonba/signature/Signer.hpp>
#include <memory>

namespace Alibabacloud {
namespace Credential {

bool RamRoleArnProvider::refreshCredential() const {
  Darabonba::Http::Query query = {
      {"Action", "AssumeRole"},
      {"Format", "JSON"},
      {"Version", "2015-04-01"},
      {"DurationSeconds", std::to_string(config_->durationSeconds())},
      {"RoleArn", (config_->roleArn())},
      {"AccessKeyId", credential_.accessKeyId()},
      {"RegionId", regionId_},
      {"RoleSessionName", (config_->roleSessionName())},
      {"SignatureMethod", "HMAC-SHA1"},
      {"SignatureVersion", "1.0"},
      {"Timestamp", gmt_datetime()},
      {"SignatureNonce", Darabonba::Core::uuid()},
  };
  if (config_->hasPolicy()) {
    query.emplace("Policy", config_->policy());
  }

  // %2F is the url_encode of '/'
  std::string stringToSign = "GET&%2F&" + std::string(query);
  std::string signature =
      Darabonba::Util::toString(Darabonba::Signature::Signer::HmacSHA1Sign(
          stringToSign, credential_.accessKeySecret()));
  query.emplace("Signature", signature);

  Darabonba::Http::Request req(std::string("https://sts.aliyuncs.com"));
  req.query() = query;
  auto future = Darabonba::Core::doAction(req);
  auto resp = future.get();
  if (resp->statusCode() == 200) {
    auto result = Darabonba::Util::readAsJSON(resp->body());
    if (result["Code"].get<std::string>() == "Success") {
      auto &credential = result["Credentials"];
      std::string accessKeyId = credential["AccessKeyId"].get<std::string>(),
                  accessKeySecret =
                      credential["AccessKeySecret"].get<std::string>(),
                  securityToken =
                      credential["SecurityToken"].get<std::string>();
      auto expiration = strtotime(credential["Expiration"].get<std::string>());

      this->expiration_ = expiration;
      credential_.setAccessKeySecret(accessKeyId)
          .setAccessKeySecret(accessKeySecret)
          .setSecurityToken(securityToken);
      return true;
      //      return std::shared_ptr<CredentialBase>(
      //          new RamRoleArnCredential(accessKeyId, accessKeySecret,
      //          securityToken,
      //                                   expiration, shared_from_this()));
    }
  }
  return false;
}

} // namespace Credential
} // namespace Alibabacloud