#ifndef ALIBABACLOUD_OPENAPIUTIL_H_
#define ALIBABACLOUD_OPENAPIUTIL_H_

#include <alibabacloud/openapi/Config.hpp>
#include <cstdint>
#include <ctime>
#include <darabonba/Model.hpp>
#include <darabonba/Type.hpp>
#include <darabonba/encode/Encoder.hpp>
#include <darabonba/http/Request.hpp>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

namespace Alibabacloud {
namespace OpenApi {
class Util {
public:
  static void convert(const Darabonba::Model &body, Darabonba::Model &content);

  static std::string getStringToSign(const Darabonba::Http::Request &request);

  static std::string getROASignature(const std::string &stringToSign,
                                     const std::string &secret);

  static std::string toForm(const Darabonba::Json &filter);

  static std::string getTimestamp() {
    char buf[80];
    time_t t = time(nullptr);
    std::strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", gmtime(&t));
    return buf;
  }

  static std::map<std::string, std::string>
  query(const Darabonba::Json &filter);

  static std::string
  getRPCSignature(const std::map<std::string, std::string> &signedParams,
                  const std::string &method, const std::string &secret);

  static std::string
  arrayToStringWithSpecifiedStyle(const Darabonba::Json &array,
                                  const std::string &prefix,
                                  const std::string &style);

  static Darabonba::Json parseToMap(const Darabonba::Json &input) {
    return input;
  }

  static std::string getEndpoint(const std::string &endpoint,
                                 bool useAccelerate,
                                 const std::string &endpointType) {
    if (useAccelerate && endpointType == "accelerate")
      return "oss-accelerate.aliyuncs.com";
    auto ret = endpoint;
    if (endpointType == "internal") {
      auto pos = endpoint.find('.');
      if (pos != std::string::npos) {
        ret.replace(pos, 1, "-internal.");
      }
    }
    return ret;
  }

  static std::string hexEncode(const Darabonba::Bytes &raw) {
    return Darabonba::Encode::Encoder::hexEncode(raw);
  }

  static Darabonba::Bytes hash(const Darabonba::Bytes &raw,
                               const std::string &signatureAlgorithm) {
    if (signatureAlgorithm.empty())
      return {};
    if (signatureAlgorithm == "ACS3-HMAC-SHA256" ||
        signatureAlgorithm == "ACS3-RSA-SHA256") {
      return Darabonba::Encode::SHA256::hash(raw);
    } else if (signatureAlgorithm == "ACS3-HMAC-SM3") {
      return Darabonba::Encode::SM3::hash(raw);
    }
    return {};
  }

  static std::string getAuthorization(const Darabonba::Http::Request &request,
                                      const std::string &signatureAlgorithm,
                                      const std::string &payload,
                                      const std::string &accessKey,
                                      const std::string &accessKeySecret);

  static std::string getEncodePath(const std::string &path) {
    return Darabonba::Encode::Encoder::pathEncode(path);
  }

  static std::string getEncodeParam(const std::string &param) {
    return Darabonba::Encode::Encoder::percentEncode(param);
  }

  static Darabonba::Bytes signatureMethod(const std::string &stringToSign,
                                          const std::string &secret,
                                          const std::string &signAlgorithm);

  // TODO
  static Darabonba::Json mapToFlatStyle(const Darabonba::Json &input);

protected:
  static std::pair<std::string, std::string>
  getCanonicalHeadersPair(const Darabonba::Http::Header &headers);

  static std::string
  getCanonicalHeaders(const Darabonba::Http::Header &headers);

  static std::string
  getCanonicalResource(const std::string &path,
                       const std::map<std::string, std::string> &query);

  static void processObject(const Darabonba::Json &obj, std::string key,
                            std::map<std::string, std::string> &out);
};
} // namespace OpenApi
} // namespace Alibabacloud
#endif
