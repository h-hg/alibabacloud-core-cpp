#ifndef ALIBABACLOUD_OPENAPIUTIL_H_
#define ALIBABACLOUD_OPENAPIUTIL_H_

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

class OpenApiUtil {
public:
  static void convert(const Darabonba::Model &body, Darabonba::Model &content);

  static std::string getStringToSign(const Darabonba::Http::Request &request);
  static std::string
  getStringToSign(std::shared_ptr<Darabonba::Http::Request> request) {
    return request ? getStringToSign(*request) : "";
  }

  static std::string getROASignature(const std::string &stringToSign,
                                     const std::string &secret);
  static std::string getROASignature(std::shared_ptr<std::string> stringToSign,
                                     std::shared_ptr<std::string> secret) {
    return stringToSign && secret ? getROASignature(*stringToSign, *secret)
                                  : "";
  }

  static std::string toForm(const Darabonba::Json &filter);

  static std::string getTimestamp() {
    char buf[80];
    time_t t = time(nullptr);
    std::strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", gmtime(&t));
    return buf;
  }

  static std::map<std::string, std::string>
  query(std::shared_ptr<Darabonba::Json> filter) {
    if (!filter)
      return {};
    return query(*filter);
  }
  static std::map<std::string, std::string>
  query(const Darabonba::Json &filter);

  static std::string
  getRPCSignature(const std::map<std::string, std::string> &signedParams,
                  const std::string &method, const std::string &secret);
  static std::string getRPCSignature(
      std::shared_ptr<std::map<std::string, std::string>> signedParams,
      std::shared_ptr<std::string> method,
      std::shared_ptr<std::string> secret) {
    return signedParams && method && secret
               ? getRPCSignature(*signedParams, *method, *secret)
               : "";
  }

  static std::string
  arrayToStringWithSpecifiedStyle(const Darabonba::Json &array,
                                  const std::string &prefix,
                                  const std::string &style);

  static Darabonba::Json parseToMap(const Darabonba::Json &input) {
    return input;
  }
  static Darabonba::Json parseToMap(std::shared_ptr<Darabonba::Json> input) {
    return input ? parseToMap(*input) : Darabonba::Json();
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
  static std::string getEndpoint(std::shared_ptr<std::string> endpoint,
                                 std::shared_ptr<bool> useAccelerate,
                                 std::shared_ptr<std::string> endpointType) {
    return endpoint && useAccelerate && endpointType
               ? getEndpoint(*endpoint, *useAccelerate, *endpointType)
               : "";
  }

  static std::string hexEncode(std::shared_ptr<Darabonba::Bytes> raw) {
    return raw ? hexEncode(*raw) : "";
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
  static Darabonba::Bytes
  hash(std::shared_ptr<Darabonba::Bytes> raw,
       std::shared_ptr<std::string> signatureAlgorithm) {
    return raw && signatureAlgorithm ? hash(*raw, *signatureAlgorithm)
                                     : Darabonba::Bytes();
  }

  static std::string getAuthorization(const Darabonba::Http::Request &request,
                                      const std::string &signatureAlgorithm,
                                      const std::string &payload,
                                      const std::string &accessKey,
                                      const std::string &accessKeySecret);
  static std::string
  getAuthorization(std::shared_ptr<Darabonba::Http::Request> req,
                   std::shared_ptr<std::string> signatureAlgorithm,
                   std::shared_ptr<std::string> payload,
                   std::shared_ptr<std::string> accessKey,
                   std::shared_ptr<std::string> accessKeySecret) {
    if (!req || !signatureAlgorithm || !payload || !accessKey ||
        !accessKeySecret) {
      return "";
    }
    return getAuthorization(*req, *signatureAlgorithm, *payload, *accessKey,
                            *accessKeySecret);
  }

  static std::string getEncodePath(const std::string &path) {
    return Darabonba::Encode::Encoder::pathEncode(path);
  }
  static std::string getEncodePath(std::shared_ptr<std::string> path) {
    return path ? getEncodeParam(*path) : "";
  }

  static std::string getEncodeParam(const std::string &param) {
    return Darabonba::Encode::Encoder::percentEncode(param);
  }
  static std::string getEncodeParam(std::shared_ptr<std::string> param) {
    return param ? getEncodeParam(*param) : "";
  }

  static Darabonba::Bytes signatureMethod(const std::string &stringToSign,
                                          const std::string &secret,
                                          const std::string &signAlgorithm);

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
                            Darabonba::Json &out);
};
} // namespace Alibabacloud
#endif
