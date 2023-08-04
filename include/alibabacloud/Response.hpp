#ifndef ALIBABACLOUD_RESPONSE_H_
#define ALIBABACLOUD_RESPONSE_H_

#include <darabonba/Model.hpp>
#include <darabonba/Type.hpp>
#include <darabonba/http/Header.hpp>
#include <darabonba/http/MCurlResponse.hpp>

namespace Alibabacloud {

class Response : public Darabonba::Http::ResponseBase {
public:
  class Body {
  public:
    Body() = default;
    Body(const Body &) = default;
    Body(Body &&obj)
        : type_(obj.type_), stream_(std::move(obj.stream_)),
          json_(std::move(obj.json_)) {
      obj.type_ = UNSET;
    }
    Body(std::shared_ptr<Darabonba::Http::MCurlResponseBody> stream)
        : type_(STREAM), stream_(stream) {}
    Body(const Darabonba::Json &json) : type_(JSON), json_(json) {}
    Body(Darabonba::Json &&json) : type_(JSON), json_(std::move(json)) {}

    Body &operator=(const Body &obj) {
      type_ = obj.type_;
      stream_ = obj.stream_;
      json_ = obj.json_;
      return *this;
    }
    Body &operator=(Body &&obj) {
      type_ = obj.type_;
      stream_ = std::move(obj.stream_);
      json_ = std::move(obj.json_);
      obj.type_ = UNSET;
      return *this;
    }
    Body &
    operator=(std::shared_ptr<Darabonba::Http::MCurlResponseBody> stream) {
      json_ = nullptr;
      stream_ = stream;
      type_ = STREAM;
      return *this;
    }
    Body &operator=(const Darabonba::Json &json) {
      stream_ = nullptr;
      json_ = json;
      type_ = JSON;
      return *this;
    }
    bool isStream() const { return type_ == JSON; };
    bool isJson() const { return type_ == STREAM; };

    std::shared_ptr<Darabonba::Http::MCurlResponseBody> stream() const {
      return stream_;
    }
    const Darabonba::Json &json() const { return json_; };
    Darabonba::Json &json() { return json_; }

  protected:
    enum BodyType { STREAM, JSON, UNSET };
    BodyType type_ = UNSET;
    std::shared_ptr<Darabonba::Http::MCurlResponseBody> stream_ = nullptr;
    Darabonba::Json json_ = nullptr;
  };

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

  const Body &body() const { DARABONBA_GET(body_); }
  Body &body() { DARABONBA_GET(body_); }
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

protected:
  Body body_;
};

} // namespace Alibabacloud

#endif