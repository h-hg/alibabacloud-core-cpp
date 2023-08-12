#ifndef ALIBABACLOUD_OPENAPI_CLIENT_H_
#define ALIBABACLOUD_OPENAPI_CLIENT_H_

#include <alibabacloud/gateway/SPI.hpp>
#include <alibabacloud/openapi/Config.hpp>
#include <alibabacloud/openapi/Exception.hpp>
#include <alibabacloud/openapi/GlobalParameters.hpp>
#include <alibabacloud/openapi/Params.hpp>
#include <alibabacloud/openapi/Request.hpp>
#include <alibabacloud/openapi/Response.hpp>
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
                        const std::string &bodyType, const Request &request,
                        const Darabonba::RuntimeOptions &runtime);

  Response doROARequest(const std::string &action, const std::string &version,
                        const std::string &protocol, const std::string &method,
                        const std::string &authType,
                        const std::string &pathname,
                        const std::string &bodyType, const Request &request,
                        const Darabonba::RuntimeOptions &runtime);

  Response
  doROARequestWithForm(const std::string &action, const std::string &version,
                       const std::string &protocol, const std::string &method,
                       const std::string &authType, const std::string &pathname,
                       const std::string &bodyType, const Request &request,
                       const Darabonba::RuntimeOptions &runtime);

  Response doRequest(const Params &params, const Request &request,
                     const Darabonba::RuntimeOptions &runtime);

  Response execute(const Params &params, const Request &request,
                   const Darabonba::RuntimeOptions &runtime);
  Response callApi(const Params &params, const Request &request,
                   const Darabonba::RuntimeOptions &runtime);

  /**
   * Get user agent
   * @return user agent
   */
  std::string getUserAgent() {
    return Darabonba::Util::getUserAgent(userAgent_);
  }

  /**
   * Get accesskey id by using credential
   * @return accesskey id
   */
  std::string getAccessKeyId() {
    return credential_.empty() ? "" : credential_.getAccessKeyId();
  }

  /**
   * Get accesskey secret by using credential
   * @return accesskey secret
   */
  std::string getAccessKeySecret() {
    return credential_.empty() ? "" : credential_.getAccessKeySecret();
  }

  /**
   * Get security token by using credential
   * @return security token
   */
  std::string getSecurityToken() {
    return credential_.empty() ? "" : credential_.getSecurityToken();
  }

  /**
   * Get bearer token by credential
   * @return bearer token
   */
  std::string getBearerToken() {
    return credential_.empty() ? "" : credential_.getBearerToken();
  }

  /**
   * Get credential type by credential
   * @return credential type e.g. access_key
   */
  std::string getType() {
    return credential_.empty() ? "" : credential_.getType();
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
    DARABONBA_SET_VALUE(spi_, spi);
  }

  /**
   * set RPC header for debug
   * @param headers headers for debug, this header can be used only once.
   */
  Client &setRpcHeaders(const Darabonba::Http::Header &headers) {
    DARABONBA_SET_VALUE(headers_, headers);
  }

  Client &setRpcHeaders(Darabonba::Http::Header &&headers) {
    DARABONBA_SET_RVALUE(headers_, headers);
  }

  /**
   * get RPC header for debug
   */
  const Darabonba::Http::Header &getRpcHeaders() const {
    DARABONBA_GET(headers_);
  }
  Darabonba::Http::Header &getRpcHeaders() { DARABONBA_GET(headers_); }

protected:
  std::string endpoint_;

  std::string regionId_;

  std::string protocol_;

  std::string method_;

  std::string userAgent_;

  std::string endpointRule_;

  std::map<std::string, std::string> endpointMap_;

  std::string suffix_;

  int64_t readTimeout_;

  int64_t connectTimeout_;

  std::string httpProxy_;

  std::string httpsProxy_;

  std::string socks5Proxy_;

  std::string socks5NetWork_;

  std::string noProxy_;

  std::string network_;

  std::string productId_;

  int64_t maxIdleConns_;

  std::string endpointType_;

  std::string openPlatformEndpoint_;

  Credential::Client credential_;

  std::string signatureVersion_;

  std::string signatureAlgorithm_;

  Darabonba::Http::Header headers_;

  std::shared_ptr<Gateway::SPI> spi_;

  GlobalParameters globalParameters_;

  std::string key_;

  std::string cert_;

  std::string ca_;
};
} // namespace OpenApi
} // namespace Alibabacloud
#endif