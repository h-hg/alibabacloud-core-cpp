#include <alibabacloud/EndpointUtil.hpp>
#include <alibabacloud/OpenApiUtil.hpp>
#include <alibabacloud/gateway/POP.hpp>
#include <darabonba/Array.hpp>
#include <darabonba/Core.hpp>
#include <darabonba/Map.hpp>
#include <darabonba/Stream.hpp>
#include <darabonba/String.hpp>
#include <darabonba/Util.hpp>
#include <darabonba/encode/Encoder.hpp>
#include <darabonba/signature/Signer.hpp>
#include <set>
#include <sstream>
#include <unordered_set>

namespace Alibabacloud {

namespace Gateway {

POP::POP() {
  this->_sha256 = "ACS4-HMAC-SHA256";
  this->_sm3 = "ACS4-HMAC-SM3";
}

void POP::modifyConfiguration(InterceptorContext &context,
                              AttributeMap &attributeMap) {
  auto &request = context.request();
  auto &config = context.configuration();
  config.setEndpoint(getEndpoint(request.productId(), config.regionId(),
                                 config.endpointRule(), config.network(),
                                 config.suffix(), config.endpointMap(),
                                 config.endpoint()));
}

void POP::modifyRequest(InterceptorContext &context,
                        AttributeMap &attributeMap) {
  auto &request = context.request();
  auto &config = context.configuration();
  auto date = OpenApiUtil::getTimestamp();
  request.setHeaders(Darabonba::Core::merge(
                         Darabonba::Json({{"host", config.endpoint()},
                                          {"x-acs-version", request.version()},
                                          {"x-acs-action", request.action()},
                                          {"user-agent", request.userAgent()},
                                          {"x-acs-date", date},
                                          {"x-acs-signature-nonce",
                                           Darabonba::Util::getNonce()},
                                          {"accept", "application/json"}}),
                         request.headers())
                         .get<std::map<std::string, std::string>>());

  std::string signatureAlgorithm =
      Darabonba::Util::defaultString(request.signatureAlgorithm(), _sha256);
  std::string hashedRequestPayload =
      Darabonba::Encode::Encoder::hexEncode(Darabonba::Encode::Encoder::hash(
          Darabonba::Util::toBytes(""), signatureAlgorithm));
  if (!Darabonba::Util::isUnset(request.stream())) {
    auto tmp = Darabonba::Util::readAsBytes(request.stream());
    hashedRequestPayload = Darabonba::Encode::Encoder::hexEncode(
        Darabonba::Encode::Encoder::hash(tmp, signatureAlgorithm));
    request.setStream(std::make_shared<Darabonba::ISStream>(tmp));
    request.headers()["content-type"] = "application/octet-stream";
  } else {
    if (!Darabonba::Util::isUnset(request.body())) {
      if (Darabonba::Util::equalString(request.reqBodyType(), "json")) {
        auto jsonObj = Darabonba::Util::toJSONString(request.body());
        hashedRequestPayload = Darabonba::Encode::Encoder::hexEncode(
            Darabonba::Encode::Encoder::hash(Darabonba::Util::toBytes(jsonObj),
                                             signatureAlgorithm));
        request.setStream(std::make_shared<Darabonba::ISStream>(jsonObj));
        request.headers()["content-type"] = "application/json; charset=utf-8";
      } else {
        auto m = Darabonba::Util::assertAsMap(request.body());
        auto formObj = OpenApiUtil::toForm(m);
        hashedRequestPayload = Darabonba::Encode::Encoder::hexEncode(
            Darabonba::Encode::Encoder::hash(Darabonba::Util::toBytes(formObj),
                                             signatureAlgorithm));
        request.setStream(std::make_shared<Darabonba::ISStream>(formObj));
        request.headers()["content-type"] = "application/x-www-form-urlencoded";
      }
    }
  }

  if (Darabonba::Util::equalString(signatureAlgorithm, _sm3)) {
    request.headers()["x-acs-content-sm3"] = hashedRequestPayload;
  } else {
    request.headers()["x-acs-content-sha256"] = hashedRequestPayload;
  }

  if (!Darabonba::Util::equalString(request.authType(), "Anonymous")) {
    auto credential = request.credential();
    auto accessKeyId = credential.getAccessKeyId();
    auto accessKeySecret = credential.getAccessKeySecret();
    auto securityToken = credential.getSecurityToken();
    if (!Darabonba::Util::empty(securityToken)) {
      request.headers()["x-acs-accesskey-id"] = accessKeyId;
      request.headers()["x-acs-security-token"] = securityToken;
    }

    auto dateNew = Darabonba::String::subString(date, 0, 10);
    dateNew = Darabonba::String::replace(dateNew, "-", "");
    auto region = getRegion(request.productId(), config.endpoint());
    auto signingkey = getSigningkey(signatureAlgorithm, accessKeySecret,
                                    request.productId(), region, dateNew);
    request.headers()["Authorization"] = getAuthorization(
        request.pathname(), request.method(), request.query(),
        request.headers(), signatureAlgorithm, hashedRequestPayload,
        accessKeyId, signingkey, request.productId(), region, dateNew);
  }
}

void POP::modifyResponse(InterceptorContext &context,
                         AttributeMap &attributeMap) {
  auto request = context.request();
  auto response = context.response();
  if (Darabonba::Util::is4xx(response.statusCode()) ||
      Darabonba::Util::is5xx(response.statusCode())) {
    auto _res = Darabonba::Util::readAsJSON(response.body());
    auto err = Darabonba::Util::assertAsMap(_res);
    auto requestId = defaultAny(err["RequestId"], err["requestId"]);
    if (!Darabonba::Util::isUnset(response.headers()["x-acs-request-id"])) {
      requestId = response.headers()["x-acs-request-id"];
    }

    err["statusCode"] = response.statusCode();
    throw Darabonba::Exception(Darabonba::Json(
        {{"code", defaultAny(err["Code"], err["code"]).get<std::string>()},
         {"message", (std::ostringstream("code: ", std::ios_base::ate)
                      << response.statusCode() << ", "
                      << defaultAny(err["Message"], err["message"])
                      << " request id: " << requestId)
                         .str()},
         {"data", err}}));
  }

  if (Darabonba::Util::equalNumber(response.statusCode(), 204)) {
    Darabonba::Util::readAsString(response.body());
  } else if (Darabonba::Util::equalString(request.bodyType(), "binary")) {
    // TODO: 完全实现不了
    // response.setDeserializedBody(response.body());
  } else if (Darabonba::Util::equalString(request.bodyType(), "byte")) {
    auto byt = Darabonba::Util::readAsBytes(response.body());
    response.setDeserializedBody(byt);
  } else if (Darabonba::Util::equalString(request.bodyType(), "string")) {
    auto str = Darabonba::Util::readAsString(response.body());
    response.setDeserializedBody(str);
  } else if (Darabonba::Util::equalString(request.bodyType(), "json")) {
    auto obj = Darabonba::Util::readAsJSON(response.body());
    auto res = Darabonba::Util::assertAsMap(obj);
    response.setDeserializedBody(res);
  } else if (Darabonba::Util::equalString(request.bodyType(), "array")) {
    auto arr = Darabonba::Util::readAsJSON(response.body());
    response.setDeserializedBody(arr);
  } else {
    response.setDeserializedBody(
        Darabonba::Util::readAsString(response.body()));
  }
}

std::string
POP::getEndpoint(const std::string &productId, const std::string &regionId,
                 const std::string &endpointRule, const std::string &network,
                 const std::string &suffix,
                 const std::map<std::string, std::string> &endpointMap,
                 const std::string &endpoint) {
  if (!Darabonba::Util::empty(endpoint)) {
    return endpoint;
  }

  if (!endpointMap.empty()) {
    auto it = endpointMap.find(regionId);
    if (it != endpointMap.end())
      return it->second;
  }

  return EndpointUtil::getEndpointRules(productId, regionId, endpointRule,
                                        network, suffix);
}

Darabonba::Json POP::defaultAny(Darabonba::Json &inputValue,
                                Darabonba::Json &defaultValue) {
  if (Darabonba::Util::isUnset(inputValue)) {
    return defaultValue;
  }

  return inputValue;
}

std::string POP::getAuthorization(
    const std::string &pathname, const std::string &method,
    const Darabonba::Http::Query &query, const Darabonba::Http::Header &headers,
    const std::string &signatureAlgorithm, const std::string &payload,
    const std::string &ak, const Darabonba::Bytes &signingkey,
    const std::string &product, const std::string &region,
    const std::string &date) {
  auto signature = getSignature(pathname, method, query, headers,
                                signatureAlgorithm, payload, signingkey);
  auto signedHeaders = getSignedHeaders(headers);
  auto signedHeadersStr = Darabonba::Array::join(signedHeaders, ";");
  return signatureAlgorithm + " Credential=" + ak + "/" + date + "/" + region +
         "/" + product +
         "/aliyun_v4_request,SignedHeaders=" + signedHeadersStr +
         ",Signature=" + signature;
}

std::string POP::getSignature(const std::string &pathname,
                              const std::string &method,
                              const Darabonba::Http::Query &query,
                              const Darabonba::Http::Header &headers,
                              const std::string &signatureAlgorithm,
                              const std::string &payload,
                              const Darabonba::Bytes &signingkey) {
  std::string canonicalURI = "/";
  if (!Darabonba::Util::empty(pathname)) {
    canonicalURI = pathname;
  }

  std::string stringToSign = "";
  std::string canonicalizedResource = buildCanonicalizedResource(query);
  std::string canonicalizedHeaders = buildCanonicalizedHeaders(headers);
  std::vector<std::string> signedHeaders = getSignedHeaders(headers);
  std::string signedHeadersStr = Darabonba::Array::join(signedHeaders, ";");
  stringToSign = method + "\n" + canonicalURI + "\n" + canonicalizedResource +
                 "\n" + canonicalizedHeaders + "\n" + signedHeadersStr + "\n" +
                 payload;
  std::string hex =
      Darabonba::Encode::Encoder::hexEncode(Darabonba::Encode::Encoder::hash(
          Darabonba::Util::toBytes(stringToSign), signatureAlgorithm));
  stringToSign = signatureAlgorithm + "\n" + hex;

  Darabonba::Bytes signature = Darabonba::Util::toBytes("");
  if (Darabonba::Util::equalString(signatureAlgorithm, _sha256)) {
    signature = Darabonba::Signature::Signer::HmacSHA256SignByBytes(
        stringToSign, signingkey);
  } else if (Darabonba::Util::equalString(signatureAlgorithm, _sm3)) {
    signature = Darabonba::Signature::Signer::HmacSM3SignByBytes(stringToSign,
                                                                 signingkey);
  }

  return Darabonba::Encode::Encoder::hexEncode(signature);
}

Darabonba::Bytes POP::getSigningkey(const std::string &signatureAlgorithm,
                                    const std::string &secret,
                                    const std::string &product,
                                    const std::string &region,
                                    const std::string &date) {
  std::string sc1 = "aliyun_v4" + secret;
  Darabonba::Bytes sc2 = Darabonba::Util::toBytes("");
  if (Darabonba::Util::equalString(signatureAlgorithm, _sha256)) {
    sc2 = Darabonba::Signature::Signer::HmacSHA256Sign(date, sc1);
  } else if (Darabonba::Util::equalString(signatureAlgorithm, _sm3)) {
    sc2 = Darabonba::Signature::Signer::HmacSM3Sign(date, sc1);
  }

  Darabonba::Bytes sc3 = Darabonba::Util::toBytes("");
  if (Darabonba::Util::equalString(signatureAlgorithm, _sha256)) {
    sc3 = Darabonba::Signature::Signer::HmacSHA256SignByBytes(region, sc2);
  } else if (Darabonba::Util::equalString(signatureAlgorithm, _sm3)) {
    sc3 = Darabonba::Signature::Signer::HmacSM3SignByBytes(region, sc2);
  }

  Darabonba::Bytes sc4 = Darabonba::Util::toBytes("");
  if (Darabonba::Util::equalString(signatureAlgorithm, _sha256)) {
    sc4 = Darabonba::Signature::Signer::HmacSHA256SignByBytes(product, sc3);
  } else if (Darabonba::Util::equalString(signatureAlgorithm, _sm3)) {
    sc4 = Darabonba::Signature::Signer::HmacSM3SignByBytes(product, sc3);
  }

  Darabonba::Bytes hmac = Darabonba::Util::toBytes("");
  if (Darabonba::Util::equalString(signatureAlgorithm, _sha256)) {
    hmac = Darabonba::Signature::Signer::HmacSHA256SignByBytes(
        "aliyun_v4_request", sc4);
  } else if (Darabonba::Util::equalString(signatureAlgorithm, _sm3)) {
    hmac = Darabonba::Signature::Signer::HmacSM3SignByBytes("aliyun_v4_request",
                                                            sc4);
  }

  return hmac;
}

std::string POP::getRegion(const std::string &product,
                           const std::string &endpoint) {
  if (Darabonba::Util::empty(product) || Darabonba::Util::empty(endpoint)) {
    return "center";
  }

  std::string popcode = Darabonba::String::toLower(product);
  std::string region = Darabonba::String::replace(endpoint, popcode, "");
  region = Darabonba::String::replace(region, "aliyuncs.com", "");
  region = Darabonba::String::replace(region, ".", "");
  if (!Darabonba::Util::empty(region)) {
    return region;
  }
  return "center";
}

std::string
POP::buildCanonicalizedResource(const Darabonba::Http::Query &query) {
  std::string canonicalizedResource = "";
  for (const auto &p : query) {
    canonicalizedResource += Darabonba::Encode::Encoder::percentEncode(p.first);
    if (!p.second.empty()) {
      canonicalizedResource +=
          "=" + Darabonba::Encode::Encoder::percentEncode(p.second) + "&";
    }
  }
  canonicalizedResource.pop_back(); // remove '&'
  return canonicalizedResource;
}

// 完成
std::string
POP::buildCanonicalizedHeaders(const Darabonba::Http::Header &headers) {
  std::string canonicalizedHeaders = "";
  auto sortedHeaders = getSignedHeaders(headers);
  for (const auto &key : sortedHeaders) {
    auto it = headers.find(key);
    if (it != headers.end()) {
      canonicalizedHeaders +=
          key + ':' + Darabonba::String::trim(it->second) + '\n';
    }
  }
  return canonicalizedHeaders;
}

// 完成
std::vector<std::string>
POP::getSignedHeaders(const Darabonba::Http::Header &headers) {
  std::set<std::string> ret;

  for (const auto &p : headers) {
    auto lowerKey = Darabonba::String::toLower(p.first);
    if (Darabonba::String::hasPrefix(lowerKey, "x-acs-") ||
        Darabonba::String::equals(lowerKey, "host") ||
        Darabonba::String::equals(lowerKey, "content-type")) {
      ret.insert(lowerKey);
    }
  }
  return {ret.begin(), ret.end()};
}

} // namespace Gateway
} // namespace Alibabacloud