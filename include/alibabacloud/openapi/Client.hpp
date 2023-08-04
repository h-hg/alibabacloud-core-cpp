#ifndef ALIBABACLOUD_OPENAPI_CLIENT_H_
#define ALIBABACLOUD_OPENAPI_CLIENT_H_

#include <alibabacloud/Response.hpp>
#include <alibabacloud/gateway/SPI.hpp>
#include <alibabacloud/openapi/Config.hpp>
#include <alibabacloud/openapi/GlobalParameters.hpp>
#include <alibabacloud/openapi/OpenApiRequest.hpp>
#include <alibabacloud/openapi/Params.hpp>
#include <darabonba/Model.hpp>
#include <darabonba/RuntimeOptions.hpp>
#include <darabonba/Util.hpp>

namespace Alibabacloud {

namespace OpenApi {

class Client {
public:
  /**
   * Init client with Config
   * @param config config contains the necessary information to create a client
   */
  Client(const Config &config);

  Response doRPCRequest(const std::string &action, const std::string &version,
                        const std::string &protocol, const std::string &method,
                        const std::string &authType,
                        const std::string &bodyType,
                        const OpenApiRequest &request,
                        const Darabonba::RuntimeOptions &runtime);

  Response doROARequest(const std::string &action, const std::string &version,
                        const std::string &protocol, const std::string &method,
                        const std::string &authType,
                        const std::string &pathname,
                        const std::string &bodyType,
                        const OpenApiRequest &request,
                        const Darabonba::RuntimeOptions &runtime);

  Response
  doROARequestWithForm(const std::string &action, const std::string &version,
                       const std::string &protocol, const std::string &method,
                       const std::string &authType, const std::string &pathname,
                       const std::string &bodyType,
                       const OpenApiRequest &request,
                       const Darabonba::RuntimeOptions &runtime);

  Response doRequest(const Params &params, const OpenApiRequest &request,
                     const Darabonba::RuntimeOptions &runtime);

  Response execute(const Params &params, const OpenApiRequest &request,
                   const Darabonba::RuntimeOptions &runtime);
  Response callApi(const Params &params, const OpenApiRequest &request,
                   const Darabonba::RuntimeOptions &runtime);

  /**
   * Get user agent
   * @return user agent
   */
  std::string getUserAgent() {
    return Darabonba::Util::getUserAgent(_userAgent);
  }

  /**
   * Get accesskey id by using credential
   * @return accesskey id
   */
  std::string getAccessKeyId() {
    return _credential.empty() ? "" : _credential.getAccessKeyId();
  }

  /**
   * Get accesskey secret by using credential
   * @return accesskey secret
   */
  std::string getAccessKeySecret() {
    return _credential.empty() ? "" : _credential.getAccessKeySecret();
  }

  /**
   * Get security token by using credential
   * @return security token
   */
  std::string getSecurityToken() {
    return _credential.empty() ? "" : _credential.getSecurityToken();
  }

  /**
   * Get bearer token by credential
   * @return bearer token
   */
  std::string getBearerToken() {
    return _credential.empty() ? "" : _credential.getBearerToken();
  }

  /**
   * Get credential type by credential
   * @return credential type e.g. access_key
   */
  std::string getType() {
    return _credential.empty() ? "" : _credential.getType();
  }

  /**
   * If inputValue is not null, return it or return defaultValue
   * @param inputValue  users input value
   * @param defaultValue default value
   * @return the final result
   */
  static Darabonba::Json defaultAny(Darabonba::Json &inputValue,
                                    Darabonba::Json &defaultValue);

  /**
   * If the endpointRule and config.endpoint are empty, throw error
   * @param config config contains the necessary information to create a client
   */
  void checkConfig(Config &config);

  /**
   * set gateway client
   * @param spi.
   */
  Client &setGatewayClient(std::shared_ptr<Gateway::SPI> spi) {
    DARABONBA_SET_VALUE(_spi, spi);
  }

  /**
   * set RPC header for debug
   * @param headers headers for debug, this header can be used only once.
   */
  Client &setRpcHeaders(const Darabonba::Http::Header &headers) {
    DARABONBA_SET_VALUE(_headers, headers);
  }

  Client &setRpcHeaders(Darabonba::Http::Header &&headers) {
    DARABONBA_SET_RVALUE(_headers, headers);
  }

  /**
   * get RPC header for debug
   */
  const Darabonba::Http::Header &getRpcHeaders() const {
    DARABONBA_GET(_headers);
  }
  Darabonba::Http::Header &getRpcHeaders() { DARABONBA_GET(_headers); }

protected:
  std::string _endpoint;

  std::string _regionId;

  std::string _protocol;

  std::string _method;

  std::string _userAgent;

  std::string _endpointRule;

  std::map<std::string, std::string> _endpointMap;

  std::string _suffix;

  int64_t _readTimeout;

  int64_t _connectTimeout;

  std::string _httpProxy;

  std::string _httpsProxy;

  std::string _socks5Proxy;

  std::string _socks5NetWork;

  std::string _noProxy;

  std::string _network;

  std::string _productId;

  int64_t _maxIdleConns;

  std::string _endpointType;

  std::string _openPlatformEndpoint;

  Credential::Client _credential;

  std::string _signatureVersion;

  std::string _signatureAlgorithm;

  Darabonba::Http::Header _headers;

  std::shared_ptr<Gateway::SPI> _spi;

  GlobalParameters _globalParameters;

  std::string _key;

  std::string _cert;

  std::string _ca;
};
} // namespace OpenApi
} // namespace Alibabacloud
#endif