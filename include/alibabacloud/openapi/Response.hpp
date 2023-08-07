#ifndef ALIBABACLOUD_RESPONSE_H_
#define ALIBABACLOUD_RESPONSE_H_

#include <darabonba/Model.hpp>
#include <darabonba/Type.hpp>
#include <darabonba/http/Header.hpp>
#include <darabonba/http/MCurlResponse.hpp>

namespace Alibabacloud {
namespace OpenApi {
class Response : public Darabonba::Http::ResponseBase {
public:
  Response() = default;
  Response(const Response &) = default;
  Response(Response &&) = default;
  virtual ~Response() = default;

  Response &setStatusCode(int64_t statusCode) {
    statusCode_ = statusCode;
    return *this;
  }

  Response &setHeader(const Darabonba::Http::Header &header) {
    header_ = header;
    return *this;
  }
  Response &setHeader(Darabonba::Http::Header &&header) {
    header_ = std::move(header);
    return *this;
  }

  const StreamJson &body() const { DARABONBA_GET(body_); }
  StreamJson &body() { DARABONBA_GET(body_); }
  Response &
  setBody(std::shared_ptr<Darabonba::Http::MCurlResponseBody> stream) {
    DARABONBA_SET_VALUE(body_, stream);
  }
  Response &setBody(const Darabonba::Json &json) {
    DARABONBA_SET_VALUE(body_, json);
  }
  Response &setBody(Darabonba::Json &&json) {
    DARABONBA_SET_RVALUE(body_, json);
  }
  Response &setBody(const StreamJson &body) {
    DARABONBA_SET_VALUE(body_, body);
  }
  Response &setBody(StreamJson &&body) { DARABONBA_SET_RVALUE(body_, body); }

protected:
  StreamJson body_;
};

} // namespace OpenApi
} // namespace Alibabacloud

#endif