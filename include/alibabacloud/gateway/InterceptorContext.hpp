#ifndef ALIBABACLOUD_GATEWAY_INTERCEPTORCONTEXT_H_
#define ALIBABACLOUD_GATEWAY_INTERCEPTORCONTEXT_H_

#include <alibabacloud/Type.hpp>
#include <alibabacloud/credential/Client.hpp>
#include <darabonba/Model.hpp>
#include <darabonba/Stream.hpp>
#include <darabonba/http/Header.hpp>
#include <darabonba/http/MCurlResponse.hpp>
#include <darabonba/http/Query.hpp>

namespace Alibabacloud {
namespace Gateway {

class InterceptorContext : public Darabonba::Model {
public:
  class Request : public Darabonba::Model {
    friend void to_json(Darabonba::Json &j, const Request &obj) {
      DARABONBA_PTR_TO_JSON(action, action_);
      DARABONBA_PTR_TO_JSON(authType, authType_);
      DARABONBA_PTR_TO_JSON(bodyType, bodyType_);
      DARABONBA_ANY_TO_JSON(body, body_);
      DARABONBA_PTR_TO_JSON(credential, credential_);
      DARABONBA_PTR_TO_JSON(headers, headers_);
      DARABONBA_PTR_TO_JSON(hostMap, hostMap_);
      DARABONBA_PTR_TO_JSON(method, method_);
      DARABONBA_PTR_TO_JSON(pathname, pathname_);
      DARABONBA_PTR_TO_JSON(productId, productId_);
      DARABONBA_PTR_TO_JSON(protocol, protocol_);
      DARABONBA_PTR_TO_JSON(query, query_);
      DARABONBA_PTR_TO_JSON(reqBodyType, reqBodyType_);
      DARABONBA_PTR_TO_JSON(signatureAlgorithm, signatureAlgorithm_);
      DARABONBA_PTR_TO_JSON(signatureVersion, signatureVersion_);
      // DARABONBA_PTR_TO_JSON(stream, stream_);
      DARABONBA_PTR_TO_JSON(style, style_);
      DARABONBA_PTR_TO_JSON(userAgent, userAgent_);
      DARABONBA_PTR_TO_JSON(version, version_);
    }

    friend void from_json(const Darabonba::Json &j, Request &obj) {
      DARABONBA_PTR_FROM_JSON(action, action_);
      DARABONBA_PTR_FROM_JSON(authType, authType_);
      DARABONBA_PTR_FROM_JSON(bodyType, bodyType_);
      DARABONBA_ANY_FROM_JSON(body, body_);
      DARABONBA_PTR_FROM_JSON(credential, credential_);
      DARABONBA_PTR_FROM_JSON(headers, headers_);
      DARABONBA_PTR_FROM_JSON(hostMap, hostMap_);
      DARABONBA_PTR_FROM_JSON(method, method_);
      DARABONBA_PTR_FROM_JSON(pathname, pathname_);
      DARABONBA_PTR_FROM_JSON(productId, productId_);
      DARABONBA_PTR_FROM_JSON(protocol, protocol_);
      DARABONBA_PTR_FROM_JSON(query, query_);
      DARABONBA_PTR_FROM_JSON(reqBodyType, reqBodyType_);
      DARABONBA_PTR_FROM_JSON(signatureAlgorithm, signatureAlgorithm_);
      DARABONBA_PTR_FROM_JSON(signatureVersion, signatureVersion_);
      // DARABONBA_PTR_FROM_JSON(stream, stream_);
      DARABONBA_PTR_FROM_JSON(style, style_);
      DARABONBA_PTR_FROM_JSON(userAgent, userAgent_);
      DARABONBA_PTR_FROM_JSON(version, version_);
    }

  public:
    Request() = default;
    Request(const Request &) = default;
    Request(Request &&) = default;
    Request(const Darabonba::Json &obj) { from_json(obj, *this); }

    virtual ~Request() = default;

    Request &operator=(const Request &) = default;
    Request &operator=(Request &&) = default;

    virtual void validate() const override {}

    virtual void fromMap(const Darabonba::Json &obj) override {
      from_json(obj, *this);
      validate();
    }

    virtual Darabonba::Json toMap() const override {
      Darabonba::Json obj;
      to_json(obj, *this);
      return obj;
    }

    virtual bool empty() const override {
      return action_ == nullptr && authType_ == nullptr &&
             bodyType_ == nullptr && body_ == nullptr &&
             credential_ == nullptr && headers_ == nullptr &&
             hostMap_ == nullptr && method_ == nullptr &&
             pathname_ == nullptr && productId_ == nullptr &&
             protocol_ == nullptr && query_ == nullptr &&
             reqBodyType_ == nullptr && signatureAlgorithm_ == nullptr &&
             signatureVersion_ == nullptr && stream_ == nullptr &&
             style_ == nullptr && userAgent_ == nullptr && version_ == nullptr;
    }

    bool hasAction() const { return this->action_ != nullptr; }
    std::string action() const { DARABONBA_PTR_GET_DEFAULT(action_, ""); }
    Request &setAction(const std::string &action) {
      DARABONBA_PTR_SET_VALUE(action_, action);
    }
    Request &setAction(std::string &&action) {
      DARABONBA_PTR_SET_RVALUE(action_, action);
    }

    bool hasAuthType() const { return this->authType_ != nullptr; }
    std::string authType() const { DARABONBA_PTR_GET_DEFAULT(authType_, ""); }
    Request &setAuthType(const std::string &authType) {
      DARABONBA_PTR_SET_VALUE(authType_, authType);
    }
    Request &setAuthType(std::string &&authType) {
      DARABONBA_PTR_SET_RVALUE(authType_, authType);
    }

    bool hasBodyType() const { return this->bodyType_ != nullptr; }
    std::string bodyType() const { DARABONBA_PTR_GET_DEFAULT(bodyType_, ""); }
    Request &setBodyType(const std::string &bodyType) {
      DARABONBA_PTR_SET_VALUE(bodyType_, bodyType);
    }
    Request &setBodyType(std::string &&bodyType) {
      DARABONBA_PTR_SET_RVALUE(bodyType_, bodyType);
    }

    bool hasBody() const { return this->body_ != nullptr; }
    const Darabonba::Json &body() const { DARABONBA_GET(body_); }
    Darabonba::Json &body() { DARABONBA_GET(body_); }
    Request &setBody(const Darabonba::Json &body) {
      DARABONBA_SET_VALUE(body_, body);
    }
    Request &setBody(Darabonba::Json &&body) {
      DARABONBA_SET_RVALUE(body_, body);
    }

    bool hasCredential() const { return this->credential_ != nullptr; }
    const Credential::Client &credential() const {
      DARABONBA_PTR_GET(credential_);
    }
    Credential::Client &credential() { DARABONBA_PTR_GET(credential_); }
    Request &setCredential(const Credential::Client &credential) {
      DARABONBA_PTR_SET_VALUE(credential_, credential);
    }
    Request &setCredential(Credential::Client &&credential) {
      DARABONBA_PTR_SET_RVALUE(credential_, credential);
    }

    bool hasHeaders() const { return this->headers_ != nullptr; }
    const Darabonba::Http::Header &headers() const {
      DARABONBA_PTR_GET(headers_);
    }
    Darabonba::Http::Header &headers() { DARABONBA_PTR_GET(headers_); }
    Request &setHeaders(const Darabonba::Http::Header &headers) {
      DARABONBA_PTR_SET_VALUE(headers_, headers);
    }
    Request &setHeaders(Darabonba::Http::Header &&headers) {
      DARABONBA_PTR_SET_RVALUE(headers_, headers);
    }

    bool hasHostMap() const { return this->hostMap_ != nullptr; }
    const std::map<std::string, std::string> &hostMap() const {
      DARABONBA_PTR_GET(hostMap_);
    }
    std::map<std::string, std::string> &hostMap() {
      DARABONBA_PTR_GET(hostMap_);
    }
    Request &setHostMap(const std::map<std::string, std::string> &hostMap) {
      DARABONBA_PTR_SET_VALUE(hostMap_, hostMap);
    }
    Request &setHostMap(std::map<std::string, std::string> &&hostMap) {
      DARABONBA_PTR_SET_RVALUE(hostMap_, hostMap);
    }

    bool hasMethod() const { return this->method_ != nullptr; }
    std::string method() const { DARABONBA_PTR_GET_DEFAULT(method_, ""); }
    Request &setMethod(const std::string &method) {
      DARABONBA_PTR_SET_VALUE(method_, method);
    }
    Request &setMethod(std::string &&method) {
      DARABONBA_PTR_SET_RVALUE(method_, method);
    }

    bool hasPathname() const { return this->pathname_ != nullptr; }
    std::string pathname() const { DARABONBA_PTR_GET_DEFAULT(pathname_, ""); }
    Request &setPathname(const std::string &pathname) {
      DARABONBA_PTR_SET_VALUE(pathname_, pathname);
    }
    Request &setPathname(std::string &&pathname) {
      DARABONBA_PTR_SET_RVALUE(pathname_, pathname);
    }

    bool hasProductId() const { return this->productId_ != nullptr; }
    std::string productId() const { DARABONBA_PTR_GET_DEFAULT(productId_, ""); }
    Request &setProductId(const std::string &productId) {
      DARABONBA_PTR_SET_VALUE(productId_, productId);
    }
    Request &setProductId(std::string &&productId) {
      DARABONBA_PTR_SET_RVALUE(productId_, productId);
    }

    bool hasProtocol() const { return this->protocol_ != nullptr; }
    std::string protocol() const { DARABONBA_PTR_GET_DEFAULT(protocol_, ""); }
    Request &setProtocol(const std::string &protocol) {
      DARABONBA_PTR_SET_VALUE(protocol_, protocol);
    }
    Request &setProtocol(std::string &&protocol) {
      DARABONBA_PTR_SET_RVALUE(protocol_, protocol);
    }

    bool hasQuery() const { return this->query_ != nullptr; }
    const Darabonba::Http::Query &query() const { DARABONBA_PTR_GET(query_); }
    Darabonba::Http::Query &query() { DARABONBA_PTR_GET(query_); }
    Request &setQuery(const Darabonba::Http::Query &query) {
      DARABONBA_PTR_SET_VALUE(query_, query);
    }
    Request &setQuery(Darabonba::Http::Query &&query) {
      DARABONBA_PTR_SET_RVALUE(query_, query);
    }

    bool hasReqBodyType() const { return this->reqBodyType_ != nullptr; }
    std::string reqBodyType() const {
      DARABONBA_PTR_GET_DEFAULT(reqBodyType_, "");
    }
    Request &setReqBodyType(const std::string &reqBodyType) {
      DARABONBA_PTR_SET_VALUE(reqBodyType_, reqBodyType);
    }
    Request &setReqBodyType(std::string &&reqBodyType) {
      DARABONBA_PTR_SET_RVALUE(reqBodyType_, reqBodyType);
    }

    bool hasSignatureAlgorithm() const {
      return this->signatureAlgorithm_ != nullptr;
    }
    std::string signatureAlgorithm() const {
      DARABONBA_PTR_GET_DEFAULT(signatureAlgorithm_, "");
    }
    Request &setSignatureAlgorithm(const std::string &signatureAlgorithm) {
      DARABONBA_PTR_SET_VALUE(signatureAlgorithm_, signatureAlgorithm);
    }
    Request &setSignatureAlgorithm(std::string &&signatureAlgorithm) {
      DARABONBA_PTR_SET_RVALUE(signatureAlgorithm_, signatureAlgorithm);
    }

    bool hasSignatureVersion() const {
      return this->signatureVersion_ != nullptr;
    }
    std::string signatureVersion() const {
      DARABONBA_PTR_GET_DEFAULT(signatureVersion_, "");
    }
    Request &setSignatureVersion(const std::string &signatureVersion) {
      DARABONBA_PTR_SET_VALUE(signatureVersion_, signatureVersion);
    }
    Request &setSignatureVersion(std::string &&signatureVersion) {
      DARABONBA_PTR_SET_RVALUE(signatureVersion_, signatureVersion);
    }

    bool hasStream() const { return this->stream_ != nullptr; }
    std::shared_ptr<Darabonba::IStream> stream() const {
      DARABONBA_GET(stream_);
    }
    Request &setStream(std::shared_ptr<Darabonba::IStream> stream) {
      DARABONBA_SET_VALUE(stream_, stream);
    }

    bool hasStyle() const { return this->style_ != nullptr; }
    std::string style() const { DARABONBA_PTR_GET_DEFAULT(style_, ""); }
    Request &setStyle(const std::string &style) {
      DARABONBA_PTR_SET_VALUE(style_, style);
    }
    Request &setStyle(std::string &&style) {
      DARABONBA_PTR_SET_RVALUE(style_, style);
    }

    bool hasUserAgent() const { return this->userAgent_ != nullptr; }
    std::string userAgent() const { DARABONBA_PTR_GET_DEFAULT(userAgent_, ""); }
    Request &setUserAgent(const std::string &userAgent) {
      DARABONBA_PTR_SET_VALUE(userAgent_, userAgent);
    }
    Request &setUserAgent(std::string &&userAgent) {
      DARABONBA_PTR_SET_RVALUE(userAgent_, userAgent);
    }

    bool hasVersion() const { return this->version_ != nullptr; }
    std::string version() const { DARABONBA_PTR_GET_DEFAULT(version_, ""); }
    Request &setVersion(const std::string &version) {
      DARABONBA_PTR_SET_VALUE(version_, version);
    }
    Request &setVersion(std::string &&version) {
      DARABONBA_PTR_SET_RVALUE(version_, version);
    }

  protected:
    std::shared_ptr<std::string> action_ = nullptr;
    std::shared_ptr<std::string> authType_ = nullptr;
    std::shared_ptr<std::string> bodyType_ = nullptr;
    Darabonba::Json body_ = nullptr;
    std::shared_ptr<Credential::Client> credential_ = nullptr;
    std::shared_ptr<Darabonba::Http::Header> headers_ = nullptr;
    std::shared_ptr<std::map<std::string, std::string>> hostMap_ = nullptr;
    std::shared_ptr<std::string> method_ = nullptr;
    std::shared_ptr<std::string> pathname_ = nullptr;
    std::shared_ptr<std::string> productId_ = nullptr;
    std::shared_ptr<std::string> protocol_ = nullptr;
    std::shared_ptr<Darabonba::Http::Query> query_ = nullptr;
    std::shared_ptr<std::string> reqBodyType_ = nullptr;
    std::shared_ptr<std::string> signatureAlgorithm_ = nullptr;
    std::shared_ptr<std::string> signatureVersion_ = nullptr;
    std::shared_ptr<Darabonba::IStream> stream_ = nullptr;
    std::shared_ptr<std::string> style_ = nullptr;
    std::shared_ptr<std::string> userAgent_ = nullptr;
    std::shared_ptr<std::string> version_ = nullptr;
  };

  class Configuration : public Darabonba::Model {
    friend void to_json(Darabonba::Json &j, const Configuration &obj) {
      DARABONBA_PTR_TO_JSON(endpointMap, endpointMap_);
      DARABONBA_PTR_TO_JSON(endpointRule, endpointRule_);
      DARABONBA_PTR_TO_JSON(endpointType, endpointType_);
      DARABONBA_PTR_TO_JSON(endpoint, endpoint_);
      DARABONBA_PTR_TO_JSON(network, network_);
      DARABONBA_PTR_TO_JSON(regionId, regionId_);
      DARABONBA_PTR_TO_JSON(suffix, suffix_);
    }

    friend void from_json(const Darabonba::Json &j, Configuration &obj) {
      DARABONBA_PTR_FROM_JSON(endpointMap, endpointMap_);
      DARABONBA_PTR_FROM_JSON(endpointRule, endpointRule_);
      DARABONBA_PTR_FROM_JSON(endpointType, endpointType_);
      DARABONBA_PTR_FROM_JSON(endpoint, endpoint_);
      DARABONBA_PTR_FROM_JSON(network, network_);
      DARABONBA_PTR_FROM_JSON(regionId, regionId_);
      DARABONBA_PTR_FROM_JSON(suffix, suffix_);
    }

  public:
    Configuration() = default;
    Configuration(const Configuration &) = default;
    Configuration(Configuration &&) = default;
    Configuration(const Darabonba::Json &obj) { from_json(obj, *this); }

    Configuration &operator=(const Configuration &) = default;
    Configuration &operator=(Configuration &&) = default;

    virtual ~Configuration() = default;

    virtual void validate() const override {}

    virtual void fromMap(const Darabonba::Json &obj) override {
      from_json(obj, *this);
      validate();
    }

    virtual Darabonba::Json toMap() const override {
      Darabonba::Json obj;
      to_json(obj, *this);
      return obj;
    }

    virtual bool empty() const override {
      return endpointMap_ == nullptr && endpointRule_ == nullptr &&
             endpointType_ == nullptr && endpoint_ == nullptr &&
             network_ == nullptr && regionId_ == nullptr && suffix_ == nullptr;
    }

    bool hasEndpointMap() const { return this->endpointMap_ != nullptr; }
    const std::map<std::string, std::string> &endpointMap() const {
      DARABONBA_PTR_GET(endpointMap_);
    }
    std::map<std::string, std::string> &endpointMap() {
      DARABONBA_PTR_GET(endpointMap_);
    }
    Configuration &
    setEndpointMap(const std::map<std::string, std::string> &endpointMap) {
      DARABONBA_PTR_SET_VALUE(endpointMap_, endpointMap);
    }
    Configuration &
    setEndpointMap(std::map<std::string, std::string> &&endpointMap) {
      DARABONBA_PTR_SET_RVALUE(endpointMap_, endpointMap);
    }

    bool hasEndpointRule() const { return this->endpointRule_ != nullptr; }
    std::string endpointRule() const {
      DARABONBA_PTR_GET_DEFAULT(endpointRule_, "");
    }
    Configuration &setEndpointRule(const std::string &endpointRule) {
      DARABONBA_PTR_SET_VALUE(endpointRule_, endpointRule);
    }
    Configuration &setEndpointRule(std::string &&endpointRule) {
      DARABONBA_PTR_SET_RVALUE(endpointRule_, endpointRule);
    }

    bool hasEndpointType() const { return this->endpointType_ != nullptr; }
    std::string endpointType() const {
      DARABONBA_PTR_GET_DEFAULT(endpointType_, "");
    }
    Configuration &setEndpointType(const std::string &endpointType) {
      DARABONBA_PTR_SET_VALUE(endpointType_, endpointType);
    }
    Configuration &setEndpointType(std::string &&endpointType) {
      DARABONBA_PTR_SET_RVALUE(endpointType_, endpointType);
    }

    bool hasEndpoint() const { return this->endpoint_ != nullptr; }
    std::string endpoint() const { DARABONBA_PTR_GET_DEFAULT(endpoint_, ""); }
    Configuration &setEndpoint(const std::string &endpoint) {
      DARABONBA_PTR_SET_VALUE(endpoint_, endpoint);
    }
    Configuration &setEndpoint(std::string &&endpoint) {
      DARABONBA_PTR_SET_RVALUE(endpoint_, endpoint);
    }

    bool hasNetwork() const { return this->network_ != nullptr; }
    std::string network() const { DARABONBA_PTR_GET_DEFAULT(network_, ""); }
    Configuration &setNetwork(const std::string &network) {
      DARABONBA_PTR_SET_VALUE(network_, network);
    }
    Configuration &setNetwork(std::string &&network) {
      DARABONBA_PTR_SET_RVALUE(network_, network);
    }

    bool hasRegionId() const { return this->regionId_ != nullptr; }
    std::string regionId() const { DARABONBA_PTR_GET_DEFAULT(regionId_, ""); }
    Configuration &setRegionId(const std::string &regionId) {
      DARABONBA_PTR_SET_VALUE(regionId_, regionId);
    }
    Configuration &setRegionId(std::string &&regionId) {
      DARABONBA_PTR_SET_RVALUE(regionId_, regionId);
    }

    bool hasSuffix() const { return this->suffix_ != nullptr; }
    std::string suffix() const { DARABONBA_PTR_GET_DEFAULT(suffix_, ""); }
    Configuration &setSuffix(const std::string &suffix) {
      DARABONBA_PTR_SET_VALUE(suffix_, suffix);
    }
    Configuration &setSuffix(std::string &&suffix) {
      DARABONBA_PTR_SET_RVALUE(suffix_, suffix);
    }

  protected:
    std::shared_ptr<std::map<std::string, std::string>> endpointMap_ = nullptr;
    std::shared_ptr<std::string> endpointRule_ = nullptr;
    std::shared_ptr<std::string> endpointType_ = nullptr;
    std::shared_ptr<std::string> endpoint_ = nullptr;
    std::shared_ptr<std::string> network_ = nullptr;
    std::shared_ptr<std::string> regionId_ = nullptr;
    std::shared_ptr<std::string> suffix_ = nullptr;
  };

  class Response : public Darabonba::Model {
    friend void to_json(Darabonba::Json &j, const Response &obj) {
      // DARABONBA_PTR_TO_JSON(body, body_);
      DARABONBA_PTR_TO_JSON(deserializedBody, deserializedBody_);
      DARABONBA_PTR_TO_JSON(headers, headers_);
      DARABONBA_PTR_TO_JSON(statusCode, statusCode_);
    }

    friend void from_json(const Darabonba::Json &j, Response &obj) {
      // DARABONBA_PTR_FROM_JSON(body, body_);
      DARABONBA_PTR_FROM_JSON(deserializedBody, deserializedBody_);
      DARABONBA_PTR_FROM_JSON(headers, headers_);
      DARABONBA_PTR_FROM_JSON(statusCode, statusCode_);
    }

  public:
    Response() = default;
    Response(const Response &) = default;
    Response(Response &&) = default;
    Response(const Darabonba::Json &obj) { from_json(obj, *this); }

    virtual ~Response() = default;

    Response &operator=(const Response &) = default;
    Response &operator=(Response &&) = default;

    virtual void validate() const override {}

    virtual void fromMap(const Darabonba::Json &obj) override {
      from_json(obj, *this);
      validate();
    }

    virtual Darabonba::Json toMap() const override {
      Darabonba::Json obj;
      to_json(obj, *this);
      return obj;
    }

    virtual bool empty() const override {
      return body_ == nullptr && deserializedBody_ == nullptr &&
             headers_ == nullptr && statusCode_ == nullptr;
    }

    bool hasBody() const { return this->body_ != nullptr; }
    std::shared_ptr<Darabonba::Http::MCurlResponseBody> body() const {
      DARABONBA_GET(body_);
    }
    Response &
    setBody(std::shared_ptr<Darabonba::Http::MCurlResponseBody> body) {
      DARABONBA_SET_VALUE(body_, body);
    }

    bool hasDeserializedBody() const {
      return this->deserializedBody_ != nullptr;
    }
    const StreamJson &deserializedBody() const {
      DARABONBA_PTR_GET(deserializedBody_);
    }
    StreamJson &deserializedBody() { DARABONBA_PTR_GET(deserializedBody_); }
    Response &setDeserializedBody(const Darabonba::Json &deserializedBody) {
      DARABONBA_PTR_SET_VALUE(deserializedBody_, deserializedBody);
    }
    Response &setDeserializedBody(Darabonba::Json &&deserializedBody) {
      DARABONBA_PTR_SET_RVALUE(deserializedBody_, deserializedBody);
    }
    Response &setDeserializedBody(
        std::shared_ptr<Darabonba::Http::MCurlResponseBody> deserializedBody) {
      DARABONBA_PTR_SET_RVALUE(deserializedBody_, deserializedBody);
    }

    bool hasHeaders() const { return this->headers_ != nullptr; }
    const Darabonba::Http::Header &headers() const {
      DARABONBA_PTR_GET(headers_);
    }
    Darabonba::Http::Header &headers() { DARABONBA_PTR_GET(headers_); }
    Response &setHeaders(const Darabonba::Http::Header &headers) {
      DARABONBA_PTR_SET_VALUE(headers_, headers);
    }
    Response &setHeaders(Darabonba::Http::Header &&headers) {
      DARABONBA_PTR_SET_RVALUE(headers_, headers);
    }

    bool hasStatusCode() const { return this->statusCode_ != nullptr; }
    int64_t statusCode() const { DARABONBA_PTR_GET_DEFAULT(statusCode_, 0); }
    Response &setStatusCode(int64_t statusCode) {
      DARABONBA_PTR_SET_VALUE(statusCode_, statusCode);
    }

  protected:
    std::shared_ptr<Darabonba::Http::MCurlResponseBody> body_ = nullptr;
    std::shared_ptr<StreamJson> deserializedBody_ = nullptr;
    std::shared_ptr<Darabonba::Http::Header> headers_ = nullptr;
    std::shared_ptr<int64_t> statusCode_ = nullptr;
  };

  friend void to_json(Darabonba::Json &j, const InterceptorContext &obj) {
    DARABONBA_PTR_TO_JSON(configuration, configuration_);
    DARABONBA_PTR_TO_JSON(request, request_);
    DARABONBA_PTR_TO_JSON(response, response_);
  }

  friend void from_json(const Darabonba::Json &j, InterceptorContext &obj) {
    DARABONBA_PTR_FROM_JSON(configuration, configuration_);
    DARABONBA_PTR_FROM_JSON(request, request_);
    DARABONBA_PTR_FROM_JSON(response, response_);
  }

public:
  InterceptorContext() = default;
  InterceptorContext(const InterceptorContext &) = default;
  InterceptorContext(InterceptorContext &&) = default;
  InterceptorContext(const Darabonba::Json &obj) { from_json(obj, *this); }

  virtual ~InterceptorContext() = default;

  virtual void validate() const override {}

  virtual void fromMap(const Darabonba::Json &obj) override {
    from_json(obj, *this);
    validate();
  }

  virtual Darabonba::Json toMap() const override {
    Darabonba::Json obj;
    to_json(obj, *this);
    return obj;
  }

  virtual bool empty() const override {
    return configuration_ == nullptr && request_ == nullptr &&
           response_ == nullptr;
  }

  bool hasConfiguration() const { return this->configuration_ != nullptr; }
  const Configuration &configuration() const {
    DARABONBA_PTR_GET(configuration_);
  }
  Configuration &configuration() { DARABONBA_PTR_GET(configuration_); }
  InterceptorContext &setConfiguration(const Configuration &configuration) {
    DARABONBA_PTR_SET_VALUE(configuration_, configuration);
  }
  InterceptorContext &setConfiguration(Configuration &&configuration) {
    DARABONBA_PTR_SET_RVALUE(configuration_, configuration);
  }

  bool hasRequest() const { return this->request_ != nullptr; }
  const Request &request() const { DARABONBA_PTR_GET(request_); }
  Request &request() { DARABONBA_PTR_GET(request_); }
  InterceptorContext &setRequest(const Request &request) {
    DARABONBA_PTR_SET_VALUE(request_, request);
  }
  InterceptorContext &setRequest(Request &&request) {
    DARABONBA_PTR_SET_RVALUE(request_, request);
  }

  bool hasResponse() const { return this->response_ != nullptr; }
  const Response &response() const { DARABONBA_PTR_GET(response_); }
  Response &response() { DARABONBA_PTR_GET(response_); }
  InterceptorContext &setResponse(const Response &response) {
    DARABONBA_PTR_SET_VALUE(response_, response);
  }
  InterceptorContext &setResponse(Response &&response) {
    DARABONBA_PTR_SET_RVALUE(response_, response);
  }

protected:
  std::shared_ptr<Configuration> configuration_ = nullptr;
  std::shared_ptr<Request> request_ = nullptr;
  std::shared_ptr<Response> response_ = nullptr;
};
} // namespace Gateway
} // namespace Alibabacloud

#endif