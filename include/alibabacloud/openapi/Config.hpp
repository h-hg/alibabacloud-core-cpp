#ifndef ALIBABACLOUD_OPENAPI_CONFIG_H_
#define ALIBABACLOUD_OPENAPI_CONFIG_H_

#include <alibabacloud/credential/Client.hpp>
#include <alibabacloud/openapi/GlobalParameters.hpp>
#include <darabonba/Model.hpp>

namespace Alibabacloud {
namespace OpenApi {
class Config : public Darabonba::Model {
  friend void to_json(Darabonba::Json &j, const Config &obj) {
    DARABONBA_PTR_TO_JSON(accessKeyId, accessKeyId_);
    DARABONBA_PTR_TO_JSON(accessKeySecret, accessKeySecret_);
    DARABONBA_PTR_TO_JSON(ca, ca_);
    DARABONBA_PTR_TO_JSON(cert, cert_);
    DARABONBA_PTR_TO_JSON(connectTimeout, connectTimeout_);
    DARABONBA_PTR_TO_JSON(credential, credential_);
    DARABONBA_PTR_TO_JSON(endpointType, endpointType_);
    DARABONBA_PTR_TO_JSON(endpoint, endpoint_);
    DARABONBA_PTR_TO_JSON(globalParameters, globalParameters_);
    DARABONBA_PTR_TO_JSON(httpProxy, httpProxy_);
    DARABONBA_PTR_TO_JSON(httpsProxy, httpsProxy_);
    DARABONBA_PTR_TO_JSON(key, key_);
    DARABONBA_PTR_TO_JSON(maxIdleConns, maxIdleConns_);
    DARABONBA_PTR_TO_JSON(method, method_);
    DARABONBA_PTR_TO_JSON(network, network_);
    DARABONBA_PTR_TO_JSON(noProxy, noProxy_);
    DARABONBA_PTR_TO_JSON(openPlatformEndpoint, openPlatformEndpoint_);
    DARABONBA_PTR_TO_JSON(protocol, protocol_);
    DARABONBA_PTR_TO_JSON(readTimeout, readTimeout_);
    DARABONBA_PTR_TO_JSON(regionId, regionId_);
    DARABONBA_PTR_TO_JSON(securityToken, securityToken_);
    DARABONBA_PTR_TO_JSON(signatureAlgorithm, signatureAlgorithm_);
    DARABONBA_PTR_TO_JSON(signatureVersion, signatureVersion_);
    DARABONBA_PTR_TO_JSON(socks5NetWork, socks5NetWork_);
    DARABONBA_PTR_TO_JSON(socks5Proxy, socks5Proxy_);
    DARABONBA_PTR_TO_JSON(suffix, suffix_);
    DARABONBA_PTR_TO_JSON(type, type_);
    DARABONBA_PTR_TO_JSON(userAgent, userAgent_);
  }

  friend void from_json(const Darabonba::Json &j, Config &obj) {
    DARABONBA_PTR_FROM_JSON(accessKeyId, accessKeyId_);
    DARABONBA_PTR_FROM_JSON(accessKeySecret, accessKeySecret_);
    DARABONBA_PTR_FROM_JSON(ca, ca_);
    DARABONBA_PTR_FROM_JSON(cert, cert_);
    DARABONBA_PTR_FROM_JSON(connectTimeout, connectTimeout_);
    DARABONBA_PTR_FROM_JSON(credential, credential_);
    DARABONBA_PTR_FROM_JSON(endpointType, endpointType_);
    DARABONBA_PTR_FROM_JSON(endpoint, endpoint_);
    DARABONBA_PTR_FROM_JSON(globalParameters, globalParameters_);
    DARABONBA_PTR_FROM_JSON(httpProxy, httpProxy_);
    DARABONBA_PTR_FROM_JSON(httpsProxy, httpsProxy_);
    DARABONBA_PTR_FROM_JSON(key, key_);
    DARABONBA_PTR_FROM_JSON(maxIdleConns, maxIdleConns_);
    DARABONBA_PTR_FROM_JSON(method, method_);
    DARABONBA_PTR_FROM_JSON(network, network_);
    DARABONBA_PTR_FROM_JSON(noProxy, noProxy_);
    DARABONBA_PTR_FROM_JSON(openPlatformEndpoint, openPlatformEndpoint_);
    DARABONBA_PTR_FROM_JSON(protocol, protocol_);
    DARABONBA_PTR_FROM_JSON(readTimeout, readTimeout_);
    DARABONBA_PTR_FROM_JSON(regionId, regionId_);
    DARABONBA_PTR_FROM_JSON(securityToken, securityToken_);
    DARABONBA_PTR_FROM_JSON(signatureAlgorithm, signatureAlgorithm_);
    DARABONBA_PTR_FROM_JSON(signatureVersion, signatureVersion_);
    DARABONBA_PTR_FROM_JSON(socks5NetWork, socks5NetWork_);
    DARABONBA_PTR_FROM_JSON(socks5Proxy, socks5Proxy_);
    DARABONBA_PTR_FROM_JSON(suffix, suffix_);
    DARABONBA_PTR_FROM_JSON(type, type_);
    DARABONBA_PTR_FROM_JSON(userAgent, userAgent_);
  }

public:
  Config() = default;
  Config(const Config &) = default;
  Config(Config &&) = default;
  Config(const Darabonba::Json &obj) { from_json(obj, *this); }

  virtual ~Config() = default;

  Config &operator=(const Config &) = default;
  Config &operator=(Config &&) = default;

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
    return accessKeyId_ == nullptr && accessKeySecret_ == nullptr &&
           ca_ == nullptr && cert_ == nullptr && connectTimeout_ == nullptr &&
           credential_ == nullptr && endpointType_ == nullptr &&
           endpoint_ == nullptr && globalParameters_ == nullptr &&
           httpProxy_ == nullptr && httpsProxy_ == nullptr && key_ == nullptr &&
           maxIdleConns_ == nullptr && method_ == nullptr &&
           network_ == nullptr && noProxy_ == nullptr &&
           openPlatformEndpoint_ == nullptr && protocol_ == nullptr &&
           readTimeout_ == nullptr && regionId_ == nullptr &&
           securityToken_ == nullptr && signatureAlgorithm_ == nullptr &&
           signatureVersion_ == nullptr && socks5NetWork_ == nullptr &&
           socks5Proxy_ == nullptr && suffix_ == nullptr && type_ == nullptr &&
           userAgent_ == nullptr;
  }

  bool hasAccessKeyId() const { return this->accessKeyId_ != nullptr; }
  std::string accessKeyId() const {
    DARABONBA_PTR_GET_DEFAULT(accessKeyId_, "");
  }
  Config &setAccessKeyId(const std::string &accessKeyId) {
    DARABONBA_PTR_SET_VALUE(accessKeyId_, accessKeyId);
  }
  Config &setAccessKeyId(std::string &&accessKeyId) {
    DARABONBA_PTR_SET_RVALUE(accessKeyId_, accessKeyId);
  }

  bool hasAccessKeySecret() const { return this->accessKeySecret_ != nullptr; }
  std::string accessKeySecret() const {
    DARABONBA_PTR_GET_DEFAULT(accessKeySecret_, "");
  }
  Config &setAccessKeySecret(const std::string &accessKeySecret) {
    DARABONBA_PTR_SET_VALUE(accessKeySecret_, accessKeySecret);
  }
  Config &setAccessKeySecret(std::string &&accessKeySecret) {
    DARABONBA_PTR_SET_RVALUE(accessKeySecret_, accessKeySecret);
  }

  bool hasCa() const { return this->ca_ != nullptr; }
  std::string ca() const { DARABONBA_PTR_GET_DEFAULT(ca_, ""); }
  Config &setCa(const std::string &ca) { DARABONBA_PTR_SET_VALUE(ca_, ca); }
  Config &setCa(std::string &&ca) { DARABONBA_PTR_SET_RVALUE(ca_, ca); }

  bool hasCert() const { return this->cert_ != nullptr; }
  std::string cert() const { DARABONBA_PTR_GET_DEFAULT(cert_, ""); }
  Config &setCert(const std::string &cert) {
    DARABONBA_PTR_SET_VALUE(cert_, cert);
  }
  Config &setCert(std::string &&cert) { DARABONBA_PTR_SET_RVALUE(cert_, cert); }

  bool hasConnectTimeout() const { return this->connectTimeout_ != nullptr; }
  int32_t connectTimeout() const {
    DARABONBA_PTR_GET_DEFAULT(connectTimeout_, 0);
  }
  Config &setConnectTimeout(int32_t connectTimeout) {
    DARABONBA_PTR_SET_VALUE(connectTimeout_, connectTimeout);
  }

  bool hasCredential() const { return this->credential_ != nullptr; }
  const Credential::Client &credential() const {
    DARABONBA_PTR_GET(credential_);
  }
  Credential::Client &credential() { DARABONBA_PTR_GET(credential_); }
  Config &setCredential(const Credential::Client &credential) {
    DARABONBA_PTR_SET_VALUE(credential_, credential);
  }
  Config &setCredential(Credential::Client &&credential) {
    DARABONBA_PTR_SET_RVALUE(credential_, credential);
  }

  bool hasEndpointType() const { return this->endpointType_ != nullptr; }
  std::string endpointType() const {
    DARABONBA_PTR_GET_DEFAULT(endpointType_, "");
  }
  Config &setEndpointType(const std::string &endpointType) {
    DARABONBA_PTR_SET_VALUE(endpointType_, endpointType);
  }
  Config &setEndpointType(std::string &&endpointType) {
    DARABONBA_PTR_SET_RVALUE(endpointType_, endpointType);
  }

  bool hasEndpoint() const { return this->endpoint_ != nullptr; }
  std::string endpoint() const { DARABONBA_PTR_GET_DEFAULT(endpoint_, ""); }
  Config &setEndpoint(const std::string &endpoint) {
    DARABONBA_PTR_SET_VALUE(endpoint_, endpoint);
  }
  Config &setEndpoint(std::string &&endpoint) {
    DARABONBA_PTR_SET_RVALUE(endpoint_, endpoint);
  }

  bool hasGlobalParameters() const {
    return this->globalParameters_ != nullptr;
  }
  const GlobalParameters &globalParameters() const {
    DARABONBA_PTR_GET(globalParameters_);
  }
  GlobalParameters &globalParameters() { DARABONBA_PTR_GET(globalParameters_); }
  Config &setGlobalParameters(const GlobalParameters &globalParameters) {
    DARABONBA_PTR_SET_VALUE(globalParameters_, globalParameters);
  }
  Config &setGlobalParameters(GlobalParameters &&globalParameters) {
    DARABONBA_PTR_SET_RVALUE(globalParameters_, globalParameters);
  }

  bool hasHttpProxy() const { return this->httpProxy_ != nullptr; }
  std::string httpProxy() const { DARABONBA_PTR_GET_DEFAULT(httpProxy_, ""); }
  Config &setHttpProxy(const std::string &httpProxy) {
    DARABONBA_PTR_SET_VALUE(httpProxy_, httpProxy);
  }
  Config &setHttpProxy(std::string &&httpProxy) {
    DARABONBA_PTR_SET_RVALUE(httpProxy_, httpProxy);
  }

  bool hasHttpsProxy() const { return this->httpsProxy_ != nullptr; }
  std::string httpsProxy() const { DARABONBA_PTR_GET_DEFAULT(httpsProxy_, ""); }
  Config &setHttpsProxy(const std::string &httpsProxy) {
    DARABONBA_PTR_SET_VALUE(httpsProxy_, httpsProxy);
  }
  Config &setHttpsProxy(std::string &&httpsProxy) {
    DARABONBA_PTR_SET_RVALUE(httpsProxy_, httpsProxy);
  }

  bool hasKey() const { return this->key_ != nullptr; }
  std::string key() const { DARABONBA_PTR_GET_DEFAULT(key_, ""); }
  Config &setKey(const std::string &key) { DARABONBA_PTR_SET_VALUE(key_, key); }
  Config &setKey(std::string &&key) { DARABONBA_PTR_SET_RVALUE(key_, key); }

  bool hasMaxIdleConns() const { return this->maxIdleConns_ != nullptr; }
  int32_t maxIdleConns() const { DARABONBA_PTR_GET_DEFAULT(maxIdleConns_, 0); }
  Config &setMaxIdleConns(int32_t maxIdleConns) {
    DARABONBA_PTR_SET_VALUE(maxIdleConns_, maxIdleConns);
  }

  bool hasMethod() const { return this->method_ != nullptr; }
  std::string method() const { DARABONBA_PTR_GET_DEFAULT(method_, ""); }
  Config &setMethod(const std::string &method) {
    DARABONBA_PTR_SET_VALUE(method_, method);
  }
  Config &setMethod(std::string &&method) {
    DARABONBA_PTR_SET_RVALUE(method_, method);
  }

  bool hasNetwork() const { return this->network_ != nullptr; }
  std::string network() const { DARABONBA_PTR_GET_DEFAULT(network_, ""); }
  Config &setNetwork(const std::string &network) {
    DARABONBA_PTR_SET_VALUE(network_, network);
  }
  Config &setNetwork(std::string &&network) {
    DARABONBA_PTR_SET_RVALUE(network_, network);
  }

  bool hasNoProxy() const { return this->noProxy_ != nullptr; }
  std::string noProxy() const { DARABONBA_PTR_GET_DEFAULT(noProxy_, ""); }
  Config &setNoProxy(const std::string &noProxy) {
    DARABONBA_PTR_SET_VALUE(noProxy_, noProxy);
  }
  Config &setNoProxy(std::string &&noProxy) {
    DARABONBA_PTR_SET_RVALUE(noProxy_, noProxy);
  }

  bool hasOpenPlatformEndpoint() const {
    return this->openPlatformEndpoint_ != nullptr;
  }
  std::string openPlatformEndpoint() const {
    DARABONBA_PTR_GET_DEFAULT(openPlatformEndpoint_, "");
  }
  Config &setOpenPlatformEndpoint(const std::string &openPlatformEndpoint) {
    DARABONBA_PTR_SET_VALUE(openPlatformEndpoint_, openPlatformEndpoint);
  }
  Config &setOpenPlatformEndpoint(std::string &&openPlatformEndpoint) {
    DARABONBA_PTR_SET_RVALUE(openPlatformEndpoint_, openPlatformEndpoint);
  }

  bool hasProtocol() const { return this->protocol_ != nullptr; }
  std::string protocol() const { DARABONBA_PTR_GET_DEFAULT(protocol_, ""); }
  Config &setProtocol(const std::string &protocol) {
    DARABONBA_PTR_SET_VALUE(protocol_, protocol);
  }
  Config &setProtocol(std::string &&protocol) {
    DARABONBA_PTR_SET_RVALUE(protocol_, protocol);
  }

  bool hasReadTimeout() const { return this->readTimeout_ != nullptr; }
  int32_t readTimeout() const { DARABONBA_PTR_GET_DEFAULT(readTimeout_, 0); }
  Config &setReadTimeout(int32_t readTimeout) {
    DARABONBA_PTR_SET_VALUE(readTimeout_, readTimeout);
  }

  bool hasRegionId() const { return this->regionId_ != nullptr; }
  std::string regionId() const { DARABONBA_PTR_GET_DEFAULT(regionId_, ""); }
  Config &setRegionId(const std::string &regionId) {
    DARABONBA_PTR_SET_VALUE(regionId_, regionId);
  }
  Config &setRegionId(std::string &&regionId) {
    DARABONBA_PTR_SET_RVALUE(regionId_, regionId);
  }

  bool hasSecurityToken() const { return this->securityToken_ != nullptr; }
  std::string securityToken() const {
    DARABONBA_PTR_GET_DEFAULT(securityToken_, "");
  }
  Config &setSecurityToken(const std::string &securityToken) {
    DARABONBA_PTR_SET_VALUE(securityToken_, securityToken);
  }
  Config &setSecurityToken(std::string &&securityToken) {
    DARABONBA_PTR_SET_RVALUE(securityToken_, securityToken);
  }

  bool hasSignatureAlgorithm() const {
    return this->signatureAlgorithm_ != nullptr;
  }
  std::string signatureAlgorithm() const {
    DARABONBA_PTR_GET_DEFAULT(signatureAlgorithm_, "");
  }
  Config &setSignatureAlgorithm(const std::string &signatureAlgorithm) {
    DARABONBA_PTR_SET_VALUE(signatureAlgorithm_, signatureAlgorithm);
  }
  Config &setSignatureAlgorithm(std::string &&signatureAlgorithm) {
    DARABONBA_PTR_SET_RVALUE(signatureAlgorithm_, signatureAlgorithm);
  }

  bool hasSignatureVersion() const {
    return this->signatureVersion_ != nullptr;
  }
  std::string signatureVersion() const {
    DARABONBA_PTR_GET_DEFAULT(signatureVersion_, "");
  }
  Config &setSignatureVersion(const std::string &signatureVersion) {
    DARABONBA_PTR_SET_VALUE(signatureVersion_, signatureVersion);
  }
  Config &setSignatureVersion(std::string &&signatureVersion) {
    DARABONBA_PTR_SET_RVALUE(signatureVersion_, signatureVersion);
  }

  bool hasSocks5NetWork() const { return this->socks5NetWork_ != nullptr; }
  std::string socks5NetWork() const {
    DARABONBA_PTR_GET_DEFAULT(socks5NetWork_, "");
  }
  Config &setSocks5NetWork(const std::string &socks5NetWork) {
    DARABONBA_PTR_SET_VALUE(socks5NetWork_, socks5NetWork);
  }
  Config &setSocks5NetWork(std::string &&socks5NetWork) {
    DARABONBA_PTR_SET_RVALUE(socks5NetWork_, socks5NetWork);
  }

  bool hasSocks5Proxy() const { return this->socks5Proxy_ != nullptr; }
  std::string socks5Proxy() const {
    DARABONBA_PTR_GET_DEFAULT(socks5Proxy_, "");
  }
  Config &setSocks5Proxy(const std::string &socks5Proxy) {
    DARABONBA_PTR_SET_VALUE(socks5Proxy_, socks5Proxy);
  }
  Config &setSocks5Proxy(std::string &&socks5Proxy) {
    DARABONBA_PTR_SET_RVALUE(socks5Proxy_, socks5Proxy);
  }

  bool hasSuffix() const { return this->suffix_ != nullptr; }
  std::string suffix() const { DARABONBA_PTR_GET_DEFAULT(suffix_, ""); }
  Config &setSuffix(const std::string &suffix) {
    DARABONBA_PTR_SET_VALUE(suffix_, suffix);
  }
  Config &setSuffix(std::string &&suffix) {
    DARABONBA_PTR_SET_RVALUE(suffix_, suffix);
  }

  bool hasType() const { return this->type_ != nullptr; }
  std::string type() const { DARABONBA_PTR_GET_DEFAULT(type_, ""); }
  Config &setType(const std::string &type) {
    DARABONBA_PTR_SET_VALUE(type_, type);
  }
  Config &setType(std::string &&type) { DARABONBA_PTR_SET_RVALUE(type_, type); }

  bool hasUserAgent() const { return this->userAgent_ != nullptr; }
  std::string userAgent() const { DARABONBA_PTR_GET_DEFAULT(userAgent_, ""); }
  Config &setUserAgent(const std::string &userAgent) {
    DARABONBA_PTR_SET_VALUE(userAgent_, userAgent);
  }
  Config &setUserAgent(std::string &&userAgent) {
    DARABONBA_PTR_SET_RVALUE(userAgent_, userAgent);
  }

protected:
  std::shared_ptr<std::string> accessKeyId_ = nullptr;
  std::shared_ptr<std::string> accessKeySecret_ = nullptr;
  std::shared_ptr<std::string> ca_ = nullptr;
  std::shared_ptr<std::string> cert_ = nullptr;
  std::shared_ptr<int32_t> connectTimeout_ = nullptr;
  std::shared_ptr<Credential::Client> credential_ = nullptr;
  std::shared_ptr<std::string> endpointType_ = nullptr;
  std::shared_ptr<std::string> endpoint_ = nullptr;
  std::shared_ptr<GlobalParameters> globalParameters_ = nullptr;
  std::shared_ptr<std::string> httpProxy_ = nullptr;
  std::shared_ptr<std::string> httpsProxy_ = nullptr;
  std::shared_ptr<std::string> key_ = nullptr;
  std::shared_ptr<int32_t> maxIdleConns_ = nullptr;
  std::shared_ptr<std::string> method_ = nullptr;
  std::shared_ptr<std::string> network_ = nullptr;
  std::shared_ptr<std::string> noProxy_ = nullptr;
  std::shared_ptr<std::string> openPlatformEndpoint_ = nullptr;
  std::shared_ptr<std::string> protocol_ = nullptr;
  std::shared_ptr<int32_t> readTimeout_ = nullptr;
  std::shared_ptr<std::string> regionId_ = nullptr;
  std::shared_ptr<std::string> securityToken_ = nullptr;
  std::shared_ptr<std::string> signatureAlgorithm_ = nullptr;
  std::shared_ptr<std::string> signatureVersion_ = nullptr;
  std::shared_ptr<std::string> socks5NetWork_ = nullptr;
  std::shared_ptr<std::string> socks5Proxy_ = nullptr;
  std::shared_ptr<std::string> suffix_ = nullptr;
  std::shared_ptr<std::string> type_ = nullptr;
  std::shared_ptr<std::string> userAgent_ = nullptr;
};

} // namespace OpenApi
} // namespace Alibabacloud
#endif
