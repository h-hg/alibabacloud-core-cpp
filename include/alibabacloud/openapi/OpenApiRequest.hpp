#ifndef ALIBABACLOUD_OPENAPIREQUEST_H_
#define ALIBABACLOUD_OPENAPIREQUEST_H_

#include <darabonba/Model.hpp>
#include <darabonba/Stream.hpp>
#include <darabonba/http/Header.hpp>
#include <darabonba/http/Query.hpp>

namespace Alibabacloud {
namespace OpenApi {

class OpenApiRequest : public Darabonba::Model {
  friend void to_json(Darabonba::Json &j, const OpenApiRequest &obj) {
    DARABONBA_PTR_TO_JSON(body, body_);
    DARABONBA_PTR_TO_JSON(endpointOverride, endpointOverride_);
    DARABONBA_PTR_TO_JSON(headers, headers_);
    DARABONBA_PTR_TO_JSON(hostMap, hostMap_);
    DARABONBA_PTR_TO_JSON(query, query_);
    // DARABONBA_PTR_TO_JSON(stream, stream_);
  }

  friend void from_json(const Darabonba::Json &j, OpenApiRequest &obj) {
    DARABONBA_PTR_FROM_JSON(body, body_);
    DARABONBA_PTR_FROM_JSON(endpointOverride, endpointOverride_);
    DARABONBA_PTR_FROM_JSON(headers, headers_);
    DARABONBA_PTR_FROM_JSON(hostMap, hostMap_);
    DARABONBA_PTR_FROM_JSON(query, query_);
    // DARABONBA_PTR_FROM_JSON(stream, stream_);
  }

public:
  OpenApiRequest() = default;
  OpenApiRequest(const OpenApiRequest &) = default;
  OpenApiRequest(OpenApiRequest &&) = default;
  OpenApiRequest(const Darabonba::Json &obj) { from_json(obj, *this); }

  virtual ~OpenApiRequest() = default;

  OpenApiRequest &operator=(const OpenApiRequest &) = default;
  OpenApiRequest &operator=(OpenApiRequest &&) = default;

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
    return body_ == nullptr && endpointOverride_ == nullptr &&
           headers_ == nullptr && hostMap_ == nullptr && query_ == nullptr &&
           stream_ == nullptr;
  }

  bool hasBody() const { return this->body_ != nullptr; }
  const Darabonba::Json &body() const { DARABONBA_PTR_GET(body_); }
  Darabonba::Json &body() { DARABONBA_PTR_GET(body_); }
  OpenApiRequest &setBody(const Darabonba::Json &body) {
    DARABONBA_PTR_SET_VALUE(body_, body);
  }
  OpenApiRequest &setBody(Darabonba::Json &&body) {
    DARABONBA_PTR_SET_RVALUE(body_, body);
  }

  bool hasEndpointOverride() const {
    return this->endpointOverride_ != nullptr;
  }
  std::string endpointOverride() const {
    DARABONBA_PTR_GET_DEFAULT(endpointOverride_, "");
  }
  OpenApiRequest &setEndpointOverride(const std::string &endpointOverride) {
    DARABONBA_PTR_SET_VALUE(endpointOverride_, endpointOverride);
  }
  OpenApiRequest &setEndpointOverride(std::string &&endpointOverride) {
    DARABONBA_PTR_SET_RVALUE(endpointOverride_, endpointOverride);
  }

  bool hasHeaders() const { return this->headers_ != nullptr; }
  const Darabonba::Http::Header &headers() const {
    DARABONBA_PTR_GET(headers_);
  }
  Darabonba::Http::Header &headers() { DARABONBA_PTR_GET(headers_); }
  OpenApiRequest &setHeaders(const Darabonba::Http::Header &headers) {
    DARABONBA_PTR_SET_VALUE(headers_, headers);
  }
  OpenApiRequest &setHeaders(Darabonba::Http::Header &&headers) {
    DARABONBA_PTR_SET_RVALUE(headers_, headers);
  }

  bool hasHostMap() const { return this->hostMap_ != nullptr; }
  const std::map<std::string, std::string> &hostMap() const {
    DARABONBA_PTR_GET(hostMap_);
  }
  std::map<std::string, std::string> &hostMap() { DARABONBA_PTR_GET(hostMap_); }
  OpenApiRequest &
  setHostMap(const std::map<std::string, std::string> &hostMap) {
    DARABONBA_PTR_SET_VALUE(hostMap_, hostMap);
  }
  OpenApiRequest &setHostMap(std::map<std::string, std::string> &&hostMap) {
    DARABONBA_PTR_SET_RVALUE(hostMap_, hostMap);
  }

  bool hasQuery() const { return this->query_ != nullptr; }
  const Darabonba::Http::Query &query() const { DARABONBA_PTR_GET(query_); }
  Darabonba::Http::Query &query() { DARABONBA_PTR_GET(query_); }
  OpenApiRequest &setQuery(const Darabonba::Http::Query &query) {
    DARABONBA_PTR_SET_VALUE(query_, query);
  }
  OpenApiRequest &setQuery(Darabonba::Http::Query &&query) {
    DARABONBA_PTR_SET_RVALUE(query_, query);
  }

  bool hasStream() const { return this->stream_ != nullptr; }
  std::shared_ptr<Darabonba::IStream> stream() const { DARABONBA_GET(stream_); }
  OpenApiRequest &setStream(std::shared_ptr<Darabonba::IStream> stream) {
    DARABONBA_SET_VALUE(stream_, stream);
  }

protected:
  std::shared_ptr<Darabonba::Json> body_ = nullptr;
  std::shared_ptr<std::string> endpointOverride_ = nullptr;
  std::shared_ptr<Darabonba::Http::Header> headers_ = nullptr;
  std::shared_ptr<std::map<std::string, std::string>> hostMap_ = nullptr;
  std::shared_ptr<Darabonba::Http::Query> query_ = nullptr;
  std::shared_ptr<Darabonba::IStream> stream_ = nullptr;
};

} // namespace OpenApi
} // namespace Alibabacloud
#endif
