#include <algorithm>
#include <alibabacloud/OpenApiUtil.hpp>
#include <darabonba/Array.hpp>
#include <darabonba/Core.hpp>
#include <darabonba/String.hpp>
#include <darabonba/Util.hpp>
#include <darabonba/encode/Encoder.hpp>
#include <darabonba/encode/SHA256.hpp>
#include <darabonba/http/Form.hpp>
#include <darabonba/http/URL.hpp>
#include <darabonba/signature/RSASigner.hpp>
#include <darabonba/signature/Signer.hpp>
#include <iostream>
#include <map>
#include <set>
#include <unordered_map>

namespace Alibabacloud {

void convert(const Darabonba::Model &body, Darabonba::Model &content) {
  auto map = body.toMap();
  // TODO:: remove the readable of map
  content.fromMap(map);
}

Darabonba::Bytes
OpenApiUtil::signatureMethod(const std::string &stringToSign,
                             const std::string &secret,
                             const std::string &signAlgorithm) {
  if (stringToSign.empty() || secret.empty() || signAlgorithm.empty())
    return {};
  if (signAlgorithm == "ACS3-HMAC-SHA256") {
    return Darabonba::Signature::Signer::HmacSHA256Sign(stringToSign, secret);
  } else if (signAlgorithm == "ACS3-HMAC-SM3") {
    return Darabonba::Signature::Signer::HmacSM3Sign(stringToSign, secret);
  } else if (signAlgorithm == "ACS3-RSA-SHA256") {
    return Darabonba::Signature::RSASigner::sign(
        reinterpret_cast<const void *>(stringToSign.c_str()),
        stringToSign.size(), reinterpret_cast<const void *>(secret.c_str()),
        secret.size(),
        std::unique_ptr<Darabonba::Encode::Hash>(
            new Darabonba::Encode::SHA256()));
  }
  return {};
}

void OpenApiUtil::processObject(const Darabonba::Json &obj, std::string key,
                                Darabonba::Json &out) {
  if (obj.is_primitive()) {
    // TODO:: Darabonba::Bytes and Json::binary_t is slight different.
    if (obj.is_binary()) {
      const auto &objReal = obj.get_ref<const Darabonba::Json::binary_t &>();
      out[key] = std::string(objReal.begin(), objReal.end());
    } else {
      out[key] = obj;
    }
  } else if (obj.is_array()) {
    for (size_t i = 0; i < obj.size(); ++i) {
      processObject(
          obj[i], (key.empty() ? key : key + '.') + std::to_string(i + 1), out);
    }
  } else if (obj.is_object()) {
    for (auto it = obj.begin(); it != obj.end(); ++it) {
      processObject(it.value(), (key.empty() ? key : key + '.') + it.key(),
                    out);
    }
  }
}

std::map<std::string, std::string>
OpenApiUtil::query(const Darabonba::Json &filter) {
  if (filter.empty() || filter.is_null())
    return {};
  Darabonba::Json ret;
  processObject(filter, "", ret);
  return ret.get<std::map<std::string, std::string>>();
}

std::string OpenApiUtil::toForm(const Darabonba::Json &filter) {
  using Form = Darabonba::Http::Form;
  std::string ret;
  for (const auto &p : query(filter)) {
    if (p.second.empty())
      continue;
    ret.append(Form::encode(p.first))
        .append("=")
        .append(Form::encode(p.second))
        .append("&");
  }
  ret.pop_back();
  return ret;
}

std::string
OpenApiUtil::arrayToStringWithSpecifiedStyle(const Darabonba::Json &array,
                                             const std::string &prefix,
                                             const std::string &style) {
  if (array.empty())
    return "";
  if (style == "repeatList") {
    Darabonba::Json obj = {{prefix, array}};
    std::string ret;
    using Form = Darabonba::Http::Form;
    for (const auto &p : query(obj)) {
      if (p.second.empty())
        continue;
      ret.append(Form::encode(p.first))
          .append("=")
          .append(Form::encode(p.second))
          .append("&&");
    }
    // remove the "&&"
    ret.resize(ret.size() - 2);
    return ret;
  } else if (style == "json") {
    return array.dump();
  } else {
    char flag;
    if (style == "simple") {
      flag = ',';
    } else if (style == "spaceDelimited") {
      flag = ' ';
    } else if (style == "pipeDelimited") {
      flag = '|';
    } else {
      return "";
    }
    std::ostringstream oss;
    for (const auto &val : array) {
      oss << val << flag;
    }
    auto ret = oss.str();
    ret.pop_back();
    return ret;
  }
  return "";
}

std::string
OpenApiUtil::getCanonicalHeaders(const Darabonba::Http::Header &headers) {
  std::map<std::string, const std::string *> canonicalKeys;
  for (const auto &p : headers) {
    if (Darabonba::String::hasPrefix(p.first, "x-acs")) {
      canonicalKeys.emplace(p.first, &p.second);
    }
  }
  std::string canonicalHeaders = "";
  for (const auto &p : canonicalKeys) {
    canonicalHeaders += p.first + ':' + *p.second + '\n';
  }
  return canonicalHeaders;
}

std::string OpenApiUtil::getCanonicalResource(
    const std::string &path, const std::map<std::string, std::string> &query) {
  if (query.empty())
    return path;
  std::string ret = path + '?';
  for (const auto &p : query) {
    if (p.first.empty())
      continue;
    if (p.second.empty()) {
      ret += p.first + '&';
    } else {
      ret += p.first + '=' + p.second + '&';
    }
  }
  ret.pop_back();
  return ret;
}

// TODO:
std::string OpenApiUtil::getStringToSign(const Darabonba::Http::Request &req) {
  auto method = req.method(), path = req.url().pathName();
  const auto &headers = req.header();
  const auto &query = req.query();
  std::string accept = "";
  auto it = headers.find("accept");
  if (it != headers.end()) {
    accept = it->second;
  }
  std::string contentMD5 = "";
  it = headers.find("content-md5");
  if (it != headers.end()) {
    contentMD5 = it->second;
  }
  std::string contentType = "";
  it = headers.find("content-type");
  if (it != headers.end()) {
    contentType = it->second;
  }
  std::string date = "";
  it = headers.find("date");
  if (it != headers.end()) {
    date = it->second;
  }
  auto header = method + '\n' + accept + '\n' + contentMD5 + '\n' +
                contentType + '\n' + date + '\n';
  auto canonicalHeaders = getCanonicalHeaders(headers);
  auto canonicalResource = getCanonicalResource(path, query);
  return header + canonicalHeaders + canonicalResource;
}

std::string OpenApiUtil::getROASignature(const std::string &stringToSign,
                                         const std::string &secret) {
  if (secret.empty())
    return "";
  auto signData =
      Darabonba::Signature::Signer::HmacSHA1Sign(stringToSign, secret);
  return Darabonba::Encode::Encoder::base64EncodeToString(signData);
}

std::string OpenApiUtil::getRPCSignature(
    const std::map<std::string, std::string> &signedParams,
    const std::string &method, const std::string &secret) {
  std::string canonicalQueryString = "";
  for (const auto &p : signedParams) {
    if (p.second.empty())
      continue;
    canonicalQueryString +=
        Darabonba::Encode::Encoder::percentEncode(p.first) + '=' +
        Darabonba::Encode::Encoder::percentEncode(p.second) + '&';
  }
  canonicalQueryString.pop_back(); // pop '&'
  // %2F is the encode of '/'
  std::string stringToSign =
      method + "&%2F" +
      Darabonba::Encode::Encoder::percentEncode(canonicalQueryString);
  auto signData =
      Darabonba::Signature::Signer::HmacSHA1Sign(stringToSign, secret + '&');
  return Darabonba::Encode::Encoder::base64EncodeToString(signData);
}

std::pair<std::string, std::string>
OpenApiUtil::getCanonicalHeadersPair(const Darabonba::Http::Header &headers) {
  std::map<std::string, std::vector<std::string>> tmpHeaders;
  std::set<std::string> canonicalKeys;
  for (const auto &p : headers) {
    auto lowerKey = Darabonba::String::toLower(p.first);
    if (Darabonba::String::hasPrefix(lowerKey, "x-acs-") ||
        lowerKey == "host" || lowerKey == "content-type") {
      canonicalKeys.insert(lowerKey);
      tmpHeaders[lowerKey].emplace_back(std::move(lowerKey));
    }
  }

  std::string canonicalHeaders = "";
  for (const auto &key : canonicalKeys) {
    canonicalHeaders +=
        key + ':' + Darabonba::Array::join(tmpHeaders[key], ",") + '\n';
  }
  return {canonicalHeaders, Darabonba::Array::join(canonicalKeys.begin(),
                                                   canonicalKeys.end(), ";")};
}

std::string OpenApiUtil::getAuthorization(const Darabonba::Http::Request &req,
                                          const std::string &signatureAlgorithm,
                                          const std::string &payload,
                                          const std::string &accessKey,
                                          const std::string &accessKeySecret) {
  auto canonicalURI = req.url().pathName();
  if (canonicalURI.empty()) {
    canonicalURI = "/";
  }

  auto canonicalQuery = std::string(req.query());
  auto p = getCanonicalHeadersPair(req.header());
  const auto &canonicalHeaders = p.first, &signedHeaders = p.second;

  std::string canonicalRequest = "";
  canonicalRequest.append(req.method())
      .append("\n")
      .append(canonicalURI)
      .append("\n")
      .append(canonicalQuery)
      .append("\n")
      .append(canonicalHeaders)
      .append("\n")
      .append(signedHeaders)
      .append("\n")
      .append(payload);
  // TODO
  Darabonba::Bytes canonicalRequestByte;
  canonicalRequestByte.assign(canonicalRequest.begin(), canonicalRequest.end());
  auto strToSign = signatureAlgorithm + '\n' +
                   hexEncode(hash(canonicalRequestByte, signatureAlgorithm));
  auto signature = hexEncode(
      signatureMethod(strToSign, accessKeySecret, signatureAlgorithm));
  return signatureAlgorithm + " Credential=" + accessKey +
         ",SignedHeaders=" + signedHeaders + ",Signature=" + signature;
}

} // namespace Alibabacloud
