#include <alibabacloud/OpenApiUtil.hpp>
#include <alibabacloud/gateway/AttributeMap.hpp>
#include <alibabacloud/gateway/InterceptorContext.hpp>
#include <alibabacloud/openapi/Client.hpp>
#include <alibabacloud/openapi/Exception.hpp>
#include <darabonba/Util.hpp>
#include <darabonba/XML.hpp>

namespace Alibabacloud {
namespace OpenApi {

/**
 * Init client with Config
 * @param config config contains the necessary information to create a client
 */
Client::Client(const Config &config_) {
  // if (Darabonba::Util::isUnset(config_.toMap())) {
  if (config_.empty()) {
    throw Darabonba::Exception("ParameterMissing: 'config' can not be unset");
  }

  auto config = config_;
  if (!Darabonba::Util::empty(config.accessKeyId()) &&
      !Darabonba::Util::empty(config.accessKeySecret())) {
    if (!Darabonba::Util::empty(config.securityToken())) {
      config.setType("sts");
    } else {
      config.setType("access_key");
    }

    Credential::Config credentialConfig;
    credentialConfig.setAccessKeyId(config.accessKeyId())
        .setAccessKeySecret(config.accessKeySecret())
        .setType(config.type())
        .setSecurityToken(config.securityToken());
    this->credential_ = Credential::Client(credentialConfig);
    // } else if (!Darabonba::Util::isUnset(config.credential())) {
  } else if (config.hasCredential()) {
    this->credential_ = config.credential();
  }

  this->endpoint_ = config.endpoint();
  this->endpointType_ = config.endpointType();
  this->network_ = config.network();
  this->suffix_ = config.suffix();
  this->protocol_ = config.protocol();
  this->method_ = config.method();
  this->regionId_ = config.regionId();
  this->userAgent_ = config.userAgent();
  this->readTimeout_ = config.readTimeout();
  this->connectTimeout_ = config.connectTimeout();
  this->httpProxy_ = config.httpProxy();
  this->httpsProxy_ = config.httpsProxy();
  this->noProxy_ = config.noProxy();
  this->socks5Proxy_ = config.socks5Proxy();
  this->socks5NetWork_ = config.socks5NetWork();
  this->maxIdleConns_ = config.maxIdleConns();
  this->signatureVersion_ = config.signatureVersion();
  this->signatureAlgorithm_ = config.signatureAlgorithm();
  if (config.hasGlobalParameters()) {
    this->globalParameters_ = config.globalParameters();
  }
  this->key_ = config.key();
  this->cert_ = config.cert();
  this->ca_ = config.ca();
}

Response
Client::doRPCRequest(const std::string &action, const std::string &version,
                     const std::string &protocol, const std::string &method,
                     const std::string &authType, const std::string &bodyType,
                     const Request &request,
                     const Darabonba::RuntimeOptions &runtime) {
  Darabonba::Json runtime_ = {
      {"timeouted", "retry"},
      {"key", Darabonba::Util::defaultString(runtime.key(), key_)},
      {"cert", Darabonba::Util::defaultString(runtime.cert(), cert_)},
      {"ca", Darabonba::Util::defaultString(runtime.ca(), ca_)},
      {"readTimeout",
       Darabonba::Util::defaultNumber(runtime.readTimeout(), readTimeout_)},
      {"connectTimeout", Darabonba::Util::defaultNumber(
                             runtime.connectTimeout(), connectTimeout_)},
      {"httpProxy",
       Darabonba::Util::defaultString(runtime.httpProxy(), httpProxy_)},
      {"httpsProxy",
       Darabonba::Util::defaultString(runtime.httpsProxy(), httpsProxy_)},
      {"noProxy", Darabonba::Util::defaultString(runtime.noProxy(), noProxy_)},
      {"socks5Proxy",
       Darabonba::Util::defaultString(runtime.socks5Proxy(), socks5Proxy_)},
      {"socks5NetWork",
       Darabonba::Util::defaultString(runtime.socks5NetWork(), socks5NetWork_)},
      {"maxIdleConns",
       Darabonba::Util::defaultNumber(runtime.maxIdleConns(), maxIdleConns_)},
      {"retry",
       {{"retryable", runtime.autoretry()},
        {"maxAttempts",
         Darabonba::Util::defaultNumber(runtime.maxAttempts(), 3)}}},
      {"backoff",
       {{"policy",
         Darabonba::Util::defaultString(runtime.backoffPolicy(), "no")},
        {"period",
         Darabonba::Util::defaultNumber(runtime.backoffPeriod(), 1)}}},
      {"ignoreSSL", runtime.ignoreSSL()}};

  Darabonba::Http::Request _lastRequest;
  Exception _lastException;
  int _retryTimes = 0;
  while (Darabonba::Core::allowRetry(runtime_["retry"], _retryTimes)) {
    if (_retryTimes > 0) {
      int backoffTime =
          Darabonba::Core::getBackoffTime(runtime_["backoff"], _retryTimes);
      if (backoffTime > 0) {
        Darabonba::Core::sleep(backoffTime);
      }
    }
    _retryTimes = _retryTimes + 1;
    try {
      Darabonba::Http::Request request_;
      request_.url().setScheme(
          Darabonba::Util::defaultString(protocol_, protocol));
      request_.setMethod(method);
      request_.url().setPathName("/");
      std::map<std::string, std::string> globalQueries = {};
      std::map<std::string, std::string> globalHeaders = {};
      // if (!Darabonba::Util::isUnset(globalParameters_)) {
      if (!globalParameters_.empty()) {
        GlobalParameters globalParams = globalParameters_;
        // if (!Darabonba::Util::isUnset(globalParams.queries())) {
        if (globalParams.hasQueries()) {
          globalQueries = globalParams.queries();
        }
        // if (!Darabonba::Util::isUnset(globalParams.headers())) {
        if (globalParams.hasHeaders()) {
          globalHeaders = globalParams.headers();
        }
      }

      request_.setQuery(
          Darabonba::Core::merge(
              Darabonba::Json(
                  {{"Action", action},
                   {"Format", "json"},
                   {"Version", version},
                   {"Timestamp", OpenApiUtil::getTimestamp()},
                   {"SignatureNonce", Darabonba::Util::getNonce()}}),
              globalQueries,
              [&]() {
                using type =
                    std::remove_reference<decltype(request.query())>::type;
                return request.hasQuery() ? request.query() : type();
              }())
              .get<std::map<std::string, std::string>>());
      std::map<std::string, std::string> headers = getRpcHeaders();
      // if (Darabonba::Util::isUnset(headers)) {
      if (headers.empty()) {
        // endpoint is setted in product client
        request_.setHeader(
            Darabonba::Core::merge(
                Darabonba::Json({{"host", endpoint_},
                                 {"x-acs-version", version},
                                 {"x-acs-action", action},
                                 {"user-agent", getUserAgent()}}),
                globalHeaders)
                .get<std::map<std::string, std::string>>());
      } else {
        request_.setHeader(
            Darabonba::Core::merge(
                Darabonba::Json({{"host", endpoint_},
                                 {"x-acs-version", version},
                                 {"x-acs-action", action},
                                 {"user-agent", getUserAgent()}}),
                globalHeaders, headers)
                .get<std::map<std::string, std::string>>());
      }

      // if (!Darabonba::Util::isUnset(request.body())) {
      if (request.hasBody()) {
        Darabonba::Json m = Darabonba::Util::assertAsMap(request.body());
        Darabonba::Json tmp =
            Darabonba::Util::anyifyMapValue(OpenApiUtil::query(m));
        request_.setBody(Darabonba::Util::toFormString(tmp));
        request_.header()["content-type"] = "application/x-www-form-urlencoded";
      }

      if (!Darabonba::Util::equalString(authType, "Anonymous")) {
        std::string accessKeyId = getAccessKeyId();
        std::string accessKeySecret = getAccessKeySecret();
        std::string securityToken = getSecurityToken();
        if (!Darabonba::Util::empty(securityToken)) {
          request_.query()["SecurityToken"] = securityToken;
        }

        request_.query()["SignatureMethod"] = "HMAC-SHA1";
        request_.query()["SignatureVersion"] = "1.0";
        request_.query()["AccessKeyId"] = accessKeyId;
        Darabonba::Json t = nullptr;
        // if (!Darabonba::Util::isUnset(request.body())) {
        if (request.hasBody()) {
          t = Darabonba::Util::assertAsMap(request.body());
        }

        std::map<std::string, std::string> signedParam =
            Darabonba::Core::merge(request_.query(), OpenApiUtil::query(t))
                .get<std::map<std::string, std::string>>();
        request_.query()["Signature"] = OpenApiUtil::getRPCSignature(
            signedParam, request_.method(), accessKeySecret);
      }

      _lastRequest = request_;
      auto future = Darabonba::Core::doAction(request_, runtime_);
      auto response_ = future.get();
      if (Darabonba::Util::is4xx(response_->statusCode()) ||
          Darabonba::Util::is5xx(response_->statusCode())) {
        Darabonba::Json _res = Darabonba::Util::readAsJSON(response_->body());
        Darabonba::Json err = Darabonba::Util::assertAsMap(_res);
        err["statusCode"] = response_->statusCode();
        Exception error;
        error.setStatusCode(response_->statusCode())
            .setCode(err.value("Code", err.value("code", "")))
            .setMessage("code: " + std::to_string(response_->statusCode()) +
                        ", " + err.value("Message", err.value("message", "")) +
                        " request id: " +
                        err.value("RequestId", err.value("requestId", "")))
            .setDescription(err.value("Code", err.value("code", "")))
            .setAccessDeniedDetail(err.value(
                "AccessDeniedDetail", err.value("accessDeniedDetial", "")))
            .setData(err);
        throw error;
      }

      if (Darabonba::Util::equalString(bodyType, "binary")) {
        Response ret;
        ret.setStatusCode(response_->statusCode())
            .setHeader(response_->header())
            .setBody(response_->body());
        return ret;
      } else if (Darabonba::Util::equalString(bodyType, "byte")) {
        Response ret;
        ret.setStatusCode(response_->statusCode())
            .setHeader(response_->header())
            .setBody(Darabonba::Util::readAsBytes(response_->body()));
        return ret;
      } else if (Darabonba::Util::equalString(bodyType, "string")) {
        Response ret;
        ret.setStatusCode(response_->statusCode())
            .setHeader(response_->header())
            .setBody(Darabonba::Util::readAsString(response_->body()));
        return ret;
      } else if (Darabonba::Util::equalString(bodyType, "json")) {
        Response ret;
        ret.setStatusCode(response_->statusCode())
            .setHeader(response_->header())
            .setBody(Darabonba::Util::readAsJSON(response_->body()));
        return ret;
      } else if (Darabonba::Util::equalString(bodyType, "array")) {
        Response ret;
        ret.setStatusCode(response_->statusCode())
            .setHeader(response_->header())
            .setBody(Darabonba::Util::readAsJSON(response_->body()));
        return ret;
      } else {
        Response ret;
        ret.setStatusCode(response_->statusCode());
        ret.setHeader(response_->header());
        return ret;
      }

    } catch (Exception e) {
      _lastException = e;
      continue;
    }
  }

  throw UnretryableException(_lastRequest, _lastException);
}

Response
Client::doROARequest(const std::string &action, const std::string &version,
                     const std::string &protocol, const std::string &method,
                     const std::string &authType, const std::string &pathname,
                     const std::string &bodyType, const Request &request,
                     const Darabonba::RuntimeOptions &runtime) {
  Darabonba::Json runtime_ = {
      {"timeouted", "retry"},
      {"key", Darabonba::Util::defaultString(runtime.key(), key_)},
      {"cert", Darabonba::Util::defaultString(runtime.cert(), cert_)},
      {"ca", Darabonba::Util::defaultString(runtime.ca(), ca_)},
      {"readTimeout",
       Darabonba::Util::defaultNumber(runtime.readTimeout(), readTimeout_)},
      {"connectTimeout", Darabonba::Util::defaultNumber(
                             runtime.connectTimeout(), connectTimeout_)},
      {"httpProxy",
       Darabonba::Util::defaultString(runtime.httpProxy(), httpProxy_)},
      {"httpsProxy",
       Darabonba::Util::defaultString(runtime.httpsProxy(), httpsProxy_)},
      {"noProxy", Darabonba::Util::defaultString(runtime.noProxy(), noProxy_)},
      {"socks5Proxy",
       Darabonba::Util::defaultString(runtime.socks5Proxy(), socks5Proxy_)},
      {"socks5NetWork",
       Darabonba::Util::defaultString(runtime.socks5NetWork(), socks5NetWork_)},
      {"maxIdleConns",
       Darabonba::Util::defaultNumber(runtime.maxIdleConns(), maxIdleConns_)},
      {"retry",
       {{"retryable", runtime.autoretry()},
        {"maxAttempts",
         Darabonba::Util::defaultNumber(runtime.maxAttempts(), 3)}}},
      {"backoff",
       {{"policy",
         Darabonba::Util::defaultString(runtime.backoffPolicy(), "no")},
        {"period",
         Darabonba::Util::defaultNumber(runtime.backoffPeriod(), 1)}}},
      {"ignoreSSL", runtime.ignoreSSL()}};

  Darabonba::Http::Request _lastRequest;
  Exception _lastException;
  int _retryTimes = 0;
  while (Darabonba::Core::allowRetry(runtime_["retry"], _retryTimes)) {
    if (_retryTimes > 0) {
      int backoffTime =
          Darabonba::Core::getBackoffTime(runtime_["backoff"], _retryTimes);
      if (backoffTime > 0) {
        Darabonba::Core::sleep(backoffTime);
      }
    }
    _retryTimes = _retryTimes + 1;
    try {
      Darabonba::Http::Request request_ = Darabonba::Http::Request();
      request_.url().setScheme(
          Darabonba::Util::defaultString(protocol_, protocol));
      request_.setMethod(method);
      request_.url().setPathName(pathname);
      std::map<std::string, std::string> globalQueries = {};
      std::map<std::string, std::string> globalHeaders = {};
      // if (!Darabonba::Util::isUnset(globalParameters_.toMap())) {
      if (!globalParameters_.empty()) {
        GlobalParameters globalParams = globalParameters_;
        // if (!Darabonba::Util::isUnset(globalParams.queries())) {
        if (globalParams.hasQueries()) {
          globalQueries = globalParams.queries();
        }

        // if (!Darabonba::Util::isUnset(globalParams.headers())) {
        if (globalParams.hasHeaders()) {
          globalHeaders = globalParams.headers();
        }
      }

      request_.setHeader(
          Darabonba::Core::merge(
              Darabonba::Json(
                  {{"date", Darabonba::Util::getDateUTCString()},
                   {"host", endpoint_},
                   {"accept", "application/json"},
                   {"x-acs-signature-nonce", Darabonba::Util::getNonce()},
                   {"x-acs-signature-method", "HMAC-SHA1"},
                   {"x-acs-signature-version", "1.0"},
                   {"x-acs-version", version},
                   {"x-acs-action", action},
                   {"user-agent", Darabonba::Util::getUserAgent(userAgent_)}}),
              globalHeaders,
              [&]() {
                using type =
                    std::remove_reference<decltype(request.headers())>::type;
                return request.hasHeaders() ? request.headers() : type();
              }())
              .get<std::map<std::string, std::string>>());
      // if (!Darabonba::Util::isUnset(request.body())) {
      if (request.hasBody()) {
        request_.setBody(request.body());
        request_.header()["content-type"] = "application/json; charset=utf-8";
      }

      request_.setQuery(globalQueries);
      // if (!Darabonba::Util::isUnset(request.query())) {
      if (request.hasQuery()) {
        request_.setQuery(
            Darabonba::Core::merge(request_.query(), request.query())
                .get<std::map<std::string, std::string>>());
      }

      if (!Darabonba::Util::equalString(authType, "Anonymous")) {
        std::string accessKeyId = getAccessKeyId();
        std::string accessKeySecret = getAccessKeySecret();
        std::string securityToken = getSecurityToken();
        if (!Darabonba::Util::empty(securityToken)) {
          request_.header()["x-acs-accesskey-id"] = accessKeyId;
          request_.header()["x-acs-security-token"] = securityToken;
        }

        std::string stringToSign = OpenApiUtil::getStringToSign(request_);
        request_.header()["authorization"] =
            (std::ostringstream("acs ", std::ios_base::ate)
             << accessKeyId << ":"
             << OpenApiUtil::getROASignature(stringToSign, accessKeySecret))
                .str();
      }

      _lastRequest = request_;
      auto future = Darabonba::Core::doAction(request_, runtime_);
      auto response_ = future.get();
      if (Darabonba::Util::equalNumber(response_->statusCode(), 204)) {
        Response ret;
        ret.setStatusCode(response_->statusCode())
            .setHeader(response_->header());
        return ret;
      }

      if (Darabonba::Util::is4xx(response_->statusCode()) ||
          Darabonba::Util::is5xx(response_->statusCode())) {
        Darabonba::Json _res = Darabonba::Util::readAsJSON(response_->body());
        Darabonba::Json err = Darabonba::Util::assertAsMap(_res);
        err["statusCode"] = response_->statusCode();
        Exception error;
        error.setStatusCode(response_->statusCode())
            .setCode(err.value("Code", err.value("code", "")))
            .setMessage("code: " + std::to_string(response_->statusCode()) +
                        ", " + err.value("Message", err.value("message", "")) +
                        " request id: " +
                        err.value("RequestId", err.value("requestId", "")))
            .setDescription(err.value("Code", err.value("code", "")))
            .setAccessDeniedDetail(err.value(
                "AccessDeniedDetail", err.value("accessDeniedDetial", "")))
            .setData(err);
        throw error;
      }

      if (Darabonba::Util::equalString(bodyType, "binary")) {
        Response ret;
        ret.setStatusCode(response_->statusCode())
            .setHeader(response_->header())
            .setBody(response_->body());
        return ret;
      } else if (Darabonba::Util::equalString(bodyType, "byte")) {
        Response ret;
        ret.setStatusCode(response_->statusCode())
            .setHeader(response_->header())
            .setBody(Darabonba::Util::readAsBytes(response_->body()));
        return ret;
      } else if (Darabonba::Util::equalString(bodyType, "string")) {
        Response ret;
        ret.setStatusCode(response_->statusCode())
            .setHeader(response_->header())
            .setBody(Darabonba::Util::readAsString(response_->body()));
        return ret;
      } else if (Darabonba::Util::equalString(bodyType, "json")) {
        Response ret;
        ret.setStatusCode(response_->statusCode())
            .setHeader(response_->header())
            .setBody(Darabonba::Util::readAsJSON(response_->body()));
        return ret;
      } else if (Darabonba::Util::equalString(bodyType, "array")) {
        Response ret;
        ret.setStatusCode(response_->statusCode())
            .setHeader(response_->header())
            .setBody(Darabonba::Util::readAsJSON(response_->body()));
        return ret;
      } else {
        Response ret;
        ret.setStatusCode(response_->statusCode())
            .setHeader(response_->header());
        return ret;
      }

    } catch (Exception e) {
      _lastException = e;
      continue;
    }
  }

  throw UnretryableException(_lastRequest, _lastException);
}

Response Client::doROARequestWithForm(
    const std::string &action, const std::string &version,
    const std::string &protocol, const std::string &method,
    const std::string &authType, const std::string &pathname,
    const std::string &bodyType, const Request &request,
    const Darabonba::RuntimeOptions &runtime) {
  Darabonba::Json runtime_ = {
      {"timeouted", "retry"},
      {"key", Darabonba::Util::defaultString(runtime.key(), key_)},
      {"cert", Darabonba::Util::defaultString(runtime.cert(), cert_)},
      {"ca", Darabonba::Util::defaultString(runtime.ca(), ca_)},
      {"readTimeout",
       Darabonba::Util::defaultNumber(runtime.readTimeout(), readTimeout_)},
      {"connectTimeout", Darabonba::Util::defaultNumber(
                             runtime.connectTimeout(), connectTimeout_)},
      {"httpProxy",
       Darabonba::Util::defaultString(runtime.httpProxy(), httpProxy_)},
      {"httpsProxy",
       Darabonba::Util::defaultString(runtime.httpsProxy(), httpsProxy_)},
      {"noProxy", Darabonba::Util::defaultString(runtime.noProxy(), noProxy_)},
      {"socks5Proxy",
       Darabonba::Util::defaultString(runtime.socks5Proxy(), socks5Proxy_)},
      {"socks5NetWork",
       Darabonba::Util::defaultString(runtime.socks5NetWork(), socks5NetWork_)},
      {"maxIdleConns",
       Darabonba::Util::defaultNumber(runtime.maxIdleConns(), maxIdleConns_)},
      {"retry",
       {{"retryable", runtime.autoretry()},
        {"maxAttempts",
         Darabonba::Util::defaultNumber(runtime.maxAttempts(), 3)}}},
      {"backoff",
       {{"policy",
         Darabonba::Util::defaultString(runtime.backoffPolicy(), "no")},
        {"period",
         Darabonba::Util::defaultNumber(runtime.backoffPeriod(), 1)}}},
      {"ignoreSSL", runtime.ignoreSSL()}};

  Darabonba::Http::Request _lastRequest;
  Exception _lastException;
  int _retryTimes = 0;
  while (Darabonba::Core::allowRetry(runtime_["retry"], _retryTimes)) {
    if (_retryTimes > 0) {
      int backoffTime =
          Darabonba::Core::getBackoffTime(runtime_["backoff"], _retryTimes);
      if (backoffTime > 0) {
        Darabonba::Core::sleep(backoffTime);
      }
    }
    _retryTimes = _retryTimes + 1;
    try {
      Darabonba::Http::Request request_ = Darabonba::Http::Request();
      request_.url().setScheme(
          Darabonba::Util::defaultString(protocol_, protocol));
      request_.setMethod(method);
      request_.url().setPathName(pathname);
      std::map<std::string, std::string> globalQueries = {};
      std::map<std::string, std::string> globalHeaders = {};
      // if (!Darabonba::Util::isUnset(globalParameters_.toMap())) {
      if (!globalParameters_.empty()) {
        GlobalParameters globalParams = globalParameters_;
        // if (!Darabonba::Util::isUnset(globalParams.queries())) {
        if (globalParams.hasQueries()) {
          globalQueries = globalParams.queries();
        }

        // if (!Darabonba::Util::isUnset(globalParams.headers())) {
        if (globalParams.hasHeaders()) {
          globalHeaders = globalParams.headers();
        }
      }

      request_.setHeader(
          Darabonba::Core::merge(
              Darabonba::Json(
                  {{"date", Darabonba::Util::getDateUTCString()},
                   {"host", endpoint_},
                   {"accept", "application/json"},
                   {"x-acs-signature-nonce", Darabonba::Util::getNonce()},
                   {"x-acs-signature-method", "HMAC-SHA1"},
                   {"x-acs-signature-version", "1.0"},
                   {"x-acs-version", version},
                   {"x-acs-action", action},
                   {"user-agent", Darabonba::Util::getUserAgent(userAgent_)}}),
              globalHeaders,
              [&]() {
                using type =
                    std::remove_reference<decltype(request.headers())>::type;
                return request.hasHeaders() ? request.headers() : type();
              }())
              .get<std::map<std::string, std::string>>());
      // if (!Darabonba::Util::isUnset(request.body())) {
      if (request.hasBody()) {
        Darabonba::Json m = Darabonba::Util::assertAsMap(request.body());
        request_.setBody(OpenApiUtil::toForm(m));
        request_.header()["content-type"] = "application/x-www-form-urlencoded";
      }

      request_.setQuery(globalQueries);
      // if (!Darabonba::Util::isUnset(request.query())) {
      if (request.hasQuery()) {
        request_.setQuery(
            Darabonba::Core::merge(
                request_.query(),
                [&]() {
                  using type =
                      std::remove_reference<decltype(request.query())>::type;
                  return request.hasQuery() ? request.query() : type();
                }())
                .get<std::map<std::string, std::string>>());
      }

      if (!Darabonba::Util::equalString(authType, "Anonymous")) {
        std::string accessKeyId = getAccessKeyId();
        std::string accessKeySecret = getAccessKeySecret();
        std::string securityToken = getSecurityToken();
        if (!Darabonba::Util::empty(securityToken)) {
          request_.header()["x-acs-accesskey-id"] = accessKeyId;
          request_.header()["x-acs-security-token"] = securityToken;
        }

        std::string stringToSign = OpenApiUtil::getStringToSign(request_);
        request_.header()["authorization"] =
            (std::ostringstream("acs ", std::ios_base::ate)
             << accessKeyId << ":"
             << OpenApiUtil::getROASignature(stringToSign, accessKeySecret))
                .str();
      }

      _lastRequest = request_;
      auto future = Darabonba::Core::doAction(request_, runtime_);
      auto response_ = future.get();

      if (Darabonba::Util::equalNumber(response_->statusCode(), 204)) {
        Response ret;
        ret.setStatusCode(response_->statusCode())
            .setHeader(response_->header());
        return ret;
      }

      if (Darabonba::Util::is4xx(response_->statusCode()) ||
          Darabonba::Util::is5xx(response_->statusCode())) {
        Darabonba::Json _res = Darabonba::Util::readAsJSON(response_->body());
        Darabonba::Json err = Darabonba::Util::assertAsMap(_res);
        err["statusCode"] = response_->statusCode();
        Exception error;
        error.setStatusCode(response_->statusCode())
            .setCode(err.value("Code", err.value("code", "")))
            .setMessage("code: " + std::to_string(response_->statusCode()) +
                        ", " + err.value("Message", err.value("message", "")) +
                        " request id: " +
                        err.value("RequestId", err.value("requestId", "")))
            .setDescription(err.value("Code", err.value("code", "")))
            .setAccessDeniedDetail(err.value(
                "AccessDeniedDetail", err.value("accessDeniedDetial", "")))
            .setData(err);
        throw error;
      }

      if (Darabonba::Util::equalString(bodyType, "binary")) {
        Response ret;
        ret.setStatusCode(response_->statusCode())
            .setHeader(response_->header())
            .setBody(response_->body());
        return ret;
      } else if (Darabonba::Util::equalString(bodyType, "byte")) {
        Response ret;
        ret.setStatusCode(response_->statusCode())
            .setHeader(response_->header())
            .setBody(Darabonba::Util::readAsBytes(response_->body()));
        return ret;
      } else if (Darabonba::Util::equalString(bodyType, "string")) {
        Response ret;
        ret.setStatusCode(response_->statusCode())
            .setHeader(response_->header())
            .setBody(Darabonba::Util::readAsString(response_->body()));
        return ret;
      } else if (Darabonba::Util::equalString(bodyType, "json")) {
        Response ret;
        ret.setStatusCode(response_->statusCode())
            .setHeader(response_->header())
            .setBody(Darabonba::Util::readAsJSON(response_->body()));
      } else if (Darabonba::Util::equalString(bodyType, "array")) {
        Response ret;
        ret.setStatusCode(response_->statusCode())
            .setHeader(response_->header())
            .setBody(Darabonba::Util::readAsJSON(response_->body()));
        return ret;
      } else {
        Response ret;
        ret.setStatusCode(response_->statusCode())
            .setHeader(response_->header());
        return ret;
      }

    } catch (Exception e) {
      _lastException = e;
      continue;
    }
  }
  throw UnretryableException(_lastRequest, _lastException);
} // namespace OpenApi

Response Client::doRequest(const Params &params, const Request &request,
                           const Darabonba::RuntimeOptions &runtime) {
  Darabonba::Json runtime_ = {
      {"timeouted", "retry"},
      {"key", Darabonba::Util::defaultString(runtime.key(), key_)},
      {"cert", Darabonba::Util::defaultString(runtime.cert(), cert_)},
      {"ca", Darabonba::Util::defaultString(runtime.ca(), ca_)},
      {"readTimeout",
       Darabonba::Util::defaultNumber(runtime.readTimeout(), readTimeout_)},
      {"connectTimeout", Darabonba::Util::defaultNumber(
                             runtime.connectTimeout(), connectTimeout_)},
      {"httpProxy",
       Darabonba::Util::defaultString(runtime.httpProxy(), httpProxy_)},
      {"httpsProxy",
       Darabonba::Util::defaultString(runtime.httpsProxy(), httpsProxy_)},
      {"noProxy", Darabonba::Util::defaultString(runtime.noProxy(), noProxy_)},
      {"socks5Proxy",
       Darabonba::Util::defaultString(runtime.socks5Proxy(), socks5Proxy_)},
      {"socks5NetWork",
       Darabonba::Util::defaultString(runtime.socks5NetWork(), socks5NetWork_)},
      {"maxIdleConns",
       Darabonba::Util::defaultNumber(runtime.maxIdleConns(), maxIdleConns_)},
      {"retry",
       {{"retryable", runtime.autoretry()},
        {"maxAttempts",
         Darabonba::Util::defaultNumber(runtime.maxAttempts(), 3)}}},
      {"backoff",
       {{"policy",
         Darabonba::Util::defaultString(runtime.backoffPolicy(), "no")},
        {"period",
         Darabonba::Util::defaultNumber(runtime.backoffPeriod(), 1)}}},
      {"ignoreSSL", runtime.ignoreSSL()}};

  Darabonba::Http::Request _lastRequest;
  Exception _lastException;
  int _retryTimes = 0;
  while (Darabonba::Core::allowRetry(runtime_["retry"], _retryTimes)) {
    if (_retryTimes > 0) {
      int backoffTime =
          Darabonba::Core::getBackoffTime(runtime_["backoff"], _retryTimes);
      if (backoffTime > 0) {
        Darabonba::Core::sleep(backoffTime);
      }
    }
    _retryTimes = _retryTimes + 1;
    try {
      Darabonba::Http::Request request_ = Darabonba::Http::Request();
      request_.url().setScheme(
          Darabonba::Util::defaultString(protocol_, params.protocol()));
      request_.setMethod(params.method());
      request_.url().setPathName(params.pathname());
      std::map<std::string, std::string> globalQueries = {};
      std::map<std::string, std::string> globalHeaders = {};
      // if (!Darabonba::Util::isUnset(globalParameters_.toMap())) {
      if (!globalParameters_.empty()) {
        GlobalParameters globalParams = globalParameters_;
        // if (!Darabonba::Util::isUnset(globalParams.queries())) {
        if (globalParams.hasQueries()) {
          globalQueries = globalParams.queries();
        }

        // if (!Darabonba::Util::isUnset(globalParams.headers())) {
        if (globalParams.hasHeaders()) {
          globalHeaders = globalParams.headers();
        }
      }

      request_.setQuery(
          Darabonba::Core::merge(
              globalQueries,
              [&]() {
                using type =
                    std::remove_reference<decltype(request.query())>::type;
                return request.hasQuery() ? request.query() : type();
              }())
              .get<std::map<std::string, std::string>>());
      // endpoint is setted in product client
      request_.setHeader(
          Darabonba::Core::merge(
              Darabonba::Json(
                  {{"host", endpoint_},
                   {"x-acs-version", params.version()},
                   {"x-acs-action", params.action()},
                   {"user-agent", getUserAgent()},
                   {"x-acs-date", OpenApiUtil::getTimestamp()},
                   {"x-acs-signature-nonce", Darabonba::Util::getNonce()},
                   {"accept", "application/json"}}),
              globalHeaders,
              [&]() {
                using type =
                    std::remove_reference<decltype(request.headers())>::type;
                return request.hasHeaders() ? request.headers() : type();
              }())
              .get<std::map<std::string, std::string>>());
      if (Darabonba::Util::equalString(params.style(), "RPC")) {
        std::map<std::string, std::string> headers = getRpcHeaders();
        // if (!Darabonba::Util::isUnset(headers)) {
        if (!headers.empty()) {
          request_.setHeader(Darabonba::Core::merge(request_.header(), headers)
                                 .get<std::map<std::string, std::string>>());
        }
      }

      std::string signatureAlgorithm = Darabonba::Util::defaultString(
          signatureAlgorithm_, "ACS3-HMAC-SHA256");
      std::string hashedRequestPayload = OpenApiUtil::hexEncode(
          OpenApiUtil::hash(Darabonba::Util::toBytes(""), signatureAlgorithm));
      // if (!Darabonba::Util::isUnset(request.stream())) {
      if (request.hasStream()) {
        Darabonba::Bytes tmp = Darabonba::Util::readAsBytes(request.stream());
        hashedRequestPayload =
            OpenApiUtil::hexEncode(OpenApiUtil::hash(tmp, signatureAlgorithm));
        request_.setBody(tmp);
        request_.header()["content-type"] = "application/octet-stream";
      } else {
        // if (!Darabonba::Util::isUnset(request.body())) {
        if (request.hasBody()) {
          if (Darabonba::Util::equalString(params.reqBodyType(), "json")) {
            std::string jsonObj = Darabonba::Util::toJSONString(request.body());
            hashedRequestPayload = OpenApiUtil::hexEncode(OpenApiUtil::hash(
                Darabonba::Util::toBytes(jsonObj), signatureAlgorithm));
            request_.setBody(jsonObj);
            request_.header()["content-type"] =
                "application/json; charset=utf-8";
          } else {
            Darabonba::Json m = Darabonba::Util::assertAsMap(request.body());
            std::string formObj = OpenApiUtil::toForm(m);
            hashedRequestPayload = OpenApiUtil::hexEncode(OpenApiUtil::hash(
                Darabonba::Util::toBytes(formObj), signatureAlgorithm));
            request_.setBody(formObj);
            request_.header()["content-type"] =
                "application/x-www-form-urlencoded";
          }
        }
      }

      request_.header()["x-acs-content-sha256"] = hashedRequestPayload;
      if (!Darabonba::Util::equalString(params.authType(), "Anonymous")) {
        std::string authType = getType();
        if (Darabonba::Util::equalString(authType, "bearer")) {
          std::string bearerToken = getBearerToken();
          request_.header()["x-acs-bearer-token"] = bearerToken;
        } else {
          std::string accessKeyId = getAccessKeyId();
          std::string accessKeySecret = getAccessKeySecret();
          std::string securityToken = getSecurityToken();
          if (!Darabonba::Util::empty(securityToken)) {
            request_.header()["x-acs-accesskey-id"] = accessKeyId;
            request_.header()["x-acs-security-token"] = securityToken;
          }

          request_.header()["Authorization"] = OpenApiUtil::getAuthorization(
              request_, signatureAlgorithm, hashedRequestPayload, accessKeyId,
              accessKeySecret);
        }
      }

      _lastRequest = request_;

      auto future = Darabonba::Core::doAction(request_, runtime_);
      auto response_ = future.get();
      if (Darabonba::Util::is4xx(response_->statusCode()) ||
          Darabonba::Util::is5xx(response_->statusCode())) {
        Darabonba::Json err = {};
        // if (!Darabonba::Util::isUnset(response_->header().at("content-type"))
        // &&
        //     Darabonba::Util::equalString(response_->header().at("content-type"),
        //                                  "text/xml;charset=utf-8")) {
        if (response_->header().count("content-type") &&
            Darabonba::Util::equalString(response_->header()["content-type"],
                                         "text/xml;charset=utf-8")) {
          std::string _str = Darabonba::Util::readAsString(response_->body());
          Darabonba::Json respMap = Darabonba::XML::parseXml(_str, nullptr);
          err = Darabonba::Util::assertAsMap(respMap["Error"]);
        } else {
          Darabonba::Json _res = Darabonba::Util::readAsJSON(response_->body());
          err = Darabonba::Util::assertAsMap(_res);
        }
        err["statusCode"] = response_->statusCode();
        Exception error;
        error.setStatusCode(response_->statusCode())
            .setCode(err.value("Code", err.value("code", "")))
            .setMessage("code: " + std::to_string(response_->statusCode()) +
                        ", " + err.value("Message", err.value("message", "")) +
                        " request id: " +
                        err.value("RequestId", err.value("requestId", "")))
            .setDescription(err.value("Code", err.value("code", "")))
            .setAccessDeniedDetail(err.value(
                "AccessDeniedDetail", err.value("accessDeniedDetial", "")))
            .setData(err);
        throw error;
      }

      if (Darabonba::Util::equalString(params.bodyType(), "binary")) {
        Response ret;
        ret.setStatusCode(response_->statusCode())
            .setHeader(response_->header())
            .setBody(response_->body());
        return ret;
      } else if (Darabonba::Util::equalString(params.bodyType(), "byte")) {
        Response ret;
        ret.setStatusCode(response_->statusCode())
            .setHeader(response_->header())
            .setBody(Darabonba::Util::readAsBytes(response_->body()));
        return ret;
      } else if (Darabonba::Util::equalString(params.bodyType(), "string")) {
        Response ret;
        ret.setStatusCode(response_->statusCode())
            .setHeader(response_->header())
            .setBody(Darabonba::Util::readAsString(response_->body()));
        return ret;
      } else if (Darabonba::Util::equalString(params.bodyType(), "json")) {
        Response ret;
        ret.setStatusCode(response_->statusCode())
            .setHeader(response_->header())
            .setBody(Darabonba::Util::readAsJSON(response_->body()));
        return ret;
      } else if (Darabonba::Util::equalString(params.bodyType(), "array")) {
        Response ret;
        ret.setStatusCode(response_->statusCode())
            .setHeader(response_->header())
            .setBody(Darabonba::Util::readAsJSON(response_->body()));
        return ret;
      } else {
        Response ret;
        ret.setStatusCode(response_->statusCode())
            .setHeader(response_->header());
        return ret;
      }

    } catch (Exception e) {
      _lastException = e;
      continue;
    }
  }
  throw UnretryableException(_lastRequest, _lastException);
}

Response Client::execute(const Params &params, const Request &request,
                         const Darabonba::RuntimeOptions &runtime) {
  Darabonba::Json runtime_ = {
      {"timeouted", "retry"},
      {"key", Darabonba::Util::defaultString(runtime.key(), key_)},
      {"cert", Darabonba::Util::defaultString(runtime.cert(), cert_)},
      {"ca", Darabonba::Util::defaultString(runtime.ca(), ca_)},
      {"readTimeout",
       Darabonba::Util::defaultNumber(runtime.readTimeout(), readTimeout_)},
      {"connectTimeout", Darabonba::Util::defaultNumber(
                             runtime.connectTimeout(), connectTimeout_)},
      {"httpProxy",
       Darabonba::Util::defaultString(runtime.httpProxy(), httpProxy_)},
      {"httpsProxy",
       Darabonba::Util::defaultString(runtime.httpsProxy(), httpsProxy_)},
      {"noProxy", Darabonba::Util::defaultString(runtime.noProxy(), noProxy_)},
      {"socks5Proxy",
       Darabonba::Util::defaultString(runtime.socks5Proxy(), socks5Proxy_)},
      {"socks5NetWork",
       Darabonba::Util::defaultString(runtime.socks5NetWork(), socks5NetWork_)},
      {"maxIdleConns",
       Darabonba::Util::defaultNumber(runtime.maxIdleConns(), maxIdleConns_)},
      {"retry",
       {{"retryable", runtime.autoretry()},
        {"maxAttempts",
         Darabonba::Util::defaultNumber(runtime.maxAttempts(), 3)}}},
      {"backoff",
       {{"policy",
         Darabonba::Util::defaultString(runtime.backoffPolicy(), "no")},
        {"period",
         Darabonba::Util::defaultNumber(runtime.backoffPeriod(), 1)}}},
      {"ignoreSSL", runtime.ignoreSSL()}};

  Darabonba::Http::Request _lastRequest;
  Exception _lastException;
  int _retryTimes = 0;
  while (Darabonba::Core::allowRetry(runtime_["retry"], _retryTimes)) {
    if (_retryTimes > 0) {
      int backoffTime =
          Darabonba::Core::getBackoffTime(runtime_["backoff"], _retryTimes);
      if (backoffTime > 0) {
        Darabonba::Core::sleep(backoffTime);
      }
    }
    _retryTimes = _retryTimes + 1;
    try {
      Darabonba::Http::Request request_ = Darabonba::Http::Request();
      // spi = new Gateway();//Gateway implements SPI，这一步在产品 SDK 中实例化
      std::map<std::string, std::string> headers = getRpcHeaders();
      std::map<std::string, std::string> globalQueries = {};
      std::map<std::string, std::string> globalHeaders = {};
      // if (!Darabonba::Util::isUnset(globalParameters_.toMap())) {
      if (!globalParameters_.empty()) {
        GlobalParameters globalParams = globalParameters_;
        // if (!Darabonba::Util::isUnset(globalParams.queries())) {
        if (globalParams.hasQueries()) {
          globalQueries = globalParams.queries();
        }

        // if (!Darabonba::Util::isUnset(globalParams.headers())) {
        if (globalParams.hasHeaders()) {
          globalHeaders = globalParams.headers();
        }
      }

      Gateway::InterceptorContext::Request requestContext;
      requestContext
          .setHeaders(Darabonba::Core::merge(
                          globalHeaders,
                          [&]() {
                            using type = std::remove_reference<
                                decltype(request.headers())>::type;
                            return request.hasHeaders() ? request.headers()
                                                        : type();
                          }(),
                          headers)
                          .get<std::map<std::string, std::string>>())
          .setQuery(
              Darabonba::Core::merge(
                  globalQueries,
                  [&]() {
                    using type =
                        std::remove_reference<decltype(request.query())>::type;
                    return request.hasQuery() ? request.query() : type();
                  }())
                  .get<std::map<std::string, std::string>>())
          .setBody(request.body())
          .setStream(request.stream())
          .setHostMap(request.hostMap())
          .setPathname(params.pathname())
          .setProductId(productId_)
          .setAction(params.action())
          .setVersion(params.version())
          .setProtocol(
              Darabonba::Util::defaultString(protocol_, params.protocol()))
          .setMethod(Darabonba::Util::defaultString(method_, params.method()))
          .setAuthType(params.authType())
          .setBodyType(params.bodyType())
          .setReqBodyType(params.reqBodyType())
          .setStyle(params.style())
          .setCredential(credential_)
          .setSignatureVersion(signatureVersion_)
          .setSignatureAlgorithm(signatureAlgorithm_)
          .setUserAgent(getUserAgent());

      Gateway::InterceptorContext::Configuration configurationContext;
      configurationContext.setRegionId(regionId_)
          .setEndpoint(Darabonba::Util::defaultString(
              request.endpointOverride(), endpoint_))
          .setEndpointRule(endpointRule_)
          .setEndpointMap(endpointMap_)
          .setEndpointType(endpointType_)
          .setNetwork(network_)
          .setSuffix(suffix_);

      Gateway::InterceptorContext interceptorContext;
      interceptorContext.setRequest(requestContext)
          .setConfiguration(configurationContext);
      Gateway::AttributeMap attributeMap;
      // 1. spi.modifyConfiguration(context: SPI.InterceptorContext,
      // attributeMap: SPI.AttributeMap);
      spi_->modifyConfiguration(interceptorContext, attributeMap);
      // 2. spi.modifyRequest(context: SPI.InterceptorContext, attributeMap:
      // SPI.AttributeMap);
      spi_->modifyRequest(interceptorContext, attributeMap);
      request_.url().setScheme(interceptorContext.request().protocol());
      request_.setMethod(interceptorContext.request().method());
      request_.url().setPathName(interceptorContext.request().pathname());
      request_.setQuery(interceptorContext.request().query());
      request_.setBody(interceptorContext.request().stream());
      request_.setHeader(interceptorContext.request().headers());
      _lastRequest = request_;
      auto future = Darabonba::Core::doAction(request_, runtime_);
      auto response_ = future.get();
      Gateway::InterceptorContext::Response responseContext;
      responseContext.setStatusCode(response_->statusCode())
          .setHeaders(response_->header())
          .setBody(response_->body());
      interceptorContext.setResponse(responseContext);
      // 3. spi.modifyResponse(context: SPI.InterceptorContext, attributeMap:
      // SPI.AttributeMap);
      spi_->modifyResponse(interceptorContext, attributeMap);
      Response ret;
      ret.setHeader(interceptorContext.response().headers())
          .setStatusCode(interceptorContext.response().statusCode())
          .setBody(interceptorContext.response().deserializedBody());
      return ret;
    } catch (Exception e) {
      _lastException = e;
      continue;
    }
  }
  throw UnretryableException(_lastRequest, _lastException);
}

Response Client::callApi(const Params &params, const Request &request,
                         const Darabonba::RuntimeOptions &runtime) {
  // if (Darabonba::Util::isUnset(params.toMap())) {
  if (params.empty()) {
    throw Darabonba::Exception("ParameterMissing: 'params' can not be unset");
  }

  // if (Darabonba::Util::isUnset(signatureAlgorithm_) ||
  //     !Darabonba::Util::equalString(signatureAlgorithm_, "v2")) {
  if (signatureAlgorithm_.empty() ||
      !Darabonba::Util::equalString(signatureAlgorithm_, "v2")) {
    return doRequest(params, request, runtime);
  } else if (Darabonba::Util::equalString(params.style(), "ROA") &&
             Darabonba::Util::equalString(params.reqBodyType(), "json")) {
    return doROARequest(params.action(), params.version(), params.protocol(),
                        params.method(), params.authType(), params.pathname(),
                        params.bodyType(), request, runtime);
  } else if (Darabonba::Util::equalString(params.style(), "ROA")) {
    return doROARequestWithForm(params.action(), params.version(),
                                params.protocol(), params.method(),
                                params.authType(), params.pathname(),
                                params.bodyType(), request, runtime);
  } else {
    return doRPCRequest(params.action(), params.version(), params.protocol(),
                        params.method(), params.authType(), params.bodyType(),
                        request, runtime);
  }
}

/**
 * If inputValue is not null, return it or return defaultValue
 * @param inputValue  users input value
 * @param defaultValue default value
 * @return the final result
 */
Darabonba::Json Client::defaultAny(Darabonba::Json &inputValue,
                                   Darabonba::Json &defaultValue) {
  if (Darabonba::Util::isUnset(inputValue)) {
    return defaultValue;
  }

  return inputValue;
}

/**
 * If the endpointRule and config.endpoint are empty, throw error
 * @param config config contains the necessary information to create a client
 */
void Client::checkConfig(Config &config) {
  if (Darabonba::Util::empty(endpointRule_) &&
      Darabonba::Util::empty(config.endpoint())) {
    throw Darabonba::Exception(
        "ParameterMissing: 'config.endpoint' can not be empty");
  }
}

} // namespace OpenApi
} // namespace Alibabacloud