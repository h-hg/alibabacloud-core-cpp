#ifndef ALIBABACLOUD_CREDENTIAL_PROVIDERBASE_H_
#define ALIBABACLOUD_CREDENTIAL_PROVIDERBASE_H_

#include <alibabacloud/credential/CredentialBase.hpp>
#include <ctime>
#include <memory>

namespace Alibabacloud {
namespace Credential {
class ProviderBase {
public:
  virtual std::shared_ptr<CredentialBase> getCredential() = 0;
  virtual ~ProviderBase() {}

protected:
  static long long strtotime(const std::string &gmt) {
    tm tm;
    strptime(gmt.c_str(), "%Y-%m-%dT%H:%M:%SZ", &tm);
    time_t t = timegm(&tm);
    return static_cast<long long>(t);
  }

  static std::string gmt_datetime() {
    time_t now;
    time(&now);
    char buf[20];
    strftime(buf, sizeof buf, "%FT%TZ", gmtime(&now));
    return buf;
  }
};
} // namespace Credential

} // namespace Alibabacloud
#endif