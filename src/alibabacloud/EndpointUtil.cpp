#include <algorithm>
#include <alibabacloud/EndpointUtil.hpp>
#include <cctype>
#include <darabonba/String.hpp>

using std::shared_ptr;
using std::string;

static string lowercase(string str) {
  std::transform(str.begin(), str.end(), str.begin(),
                 [](char c) { return std::tolower(c); });
  return str;
}

namespace Alibabacloud {

std::string EndpointUtil::getEndpointRules(const std::string &product,
                                           const std::string &regionId,
                                           const std::string &endpointType,
                                           const std::string &network,
                                           const std::string &suffix) {
  string result, networkVal, suffixVal = suffix;
  if (!network.empty() && lowercase(network) != "public") {
    networkVal = "-" + network;
  } else {
    networkVal = "";
  }

  if (!suffix.empty()) {
    suffixVal = "-" + suffix;
  }

  if (endpointType == "regional") {
    if (regionId.empty()) {
      throw std::runtime_error(
          "RegionId is empty, please set a valid RegionId");
    }
    result.append(product)
        .append(suffixVal)
        .append(networkVal + ".")
        .append(regionId)
        .append(".aliyuncs.com");
  } else {
    result.append(product).append(suffix).append(network).append(
        ".aliyuncs.com");
  }
  return lowercase(result);
}

} // namespace Alibabacloud
