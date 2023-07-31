#include <alibabacloud/credential/provider/RsaKeyPairProvider.hpp>
#include <darabonba/Core.hpp>
#include <darabonba/Util.hpp>
#include <darabonba/http/Query.hpp>
#include <darabonba/signature/Signer.hpp>

namespace Alibabacloud {
namespace Credential {

bool RsaKeyPairProvider::refreshCredential() const {
  Darabonba::Http::Query query = {
      {"Action", "GenerateSessionAccessKey"},
      {"Format", "JSON"},
      {"Version", "2015-04-01"},
      {"DurationSeconds", std::to_string(config_->durationSeconds())},
      {"AccessKeyId", credential_.accessKeyId()},
      {"RegionId", regionId_},
      {"SignatureMethod", "HMAC-SHA1"},
      {"SignatureVersion", "1.0"},
      {"Timestamp", gmt_datetime()},
      {"SignatureNonce", Darabonba::Core::uuid()},
  };

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
      auto sessionAccessKey = result["SessionAccessKey"];
      std::string accessKeyId =
                      sessionAccessKey["SessionAccessKeyId"].get<std::string>(),
                  accessKeySecret = sessionAccessKey["SessionAccessKeySecret"]
                                        .get<std::string>();
      auto expiration =
          strtotime(sessionAccessKey["Expiration"].get<std::string>());
      this->expiration_ = expiration;
      credential_.setAccessKeyId(accessKeyId)
          .setAccessKeySecret(accessKeySecret);
      return true;
    }
  }
  return false;
}

} // namespace Credential
} // namespace Alibabacloud