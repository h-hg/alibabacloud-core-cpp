#ifndef ALIBABACLOUD_OPENAPI_EXCEPTION_HPP_
#define ALIBABACLOUD_OPENAPI_EXCEPTION_HPP_

#include <darabonba/Model.hpp>
#include <darabonba/Type.hpp>
#include <darabonba/http/Request.hpp>

namespace Alibabacloud {
namespace OpenApi {

class Exception : public Darabonba::Exception {

  friend void to_json(Darabonba::Json &j, const Exception &obj) {
    DARABONBA_TO_JSON(statusCode, statusCode_);
    DARABONBA_TO_JSON(code, code_);
    DARABONBA_TO_JSON(message, message_);
    DARABONBA_TO_JSON(description, description_);
    DARABONBA_TO_JSON(accessDeniedDetail, accessDeniedDetail_);
    DARABONBA_TO_JSON(data, data_);
  }
  friend void from_json(const Darabonba::Json &j, Exception &obj) {
    DARABONBA_FROM_JSON(statusCode, statusCode_);
    DARABONBA_FROM_JSON(code, code_);
    DARABONBA_FROM_JSON(message, message_);
    DARABONBA_FROM_JSON(description, description_);
    DARABONBA_FROM_JSON(accessDeniedDetail, accessDeniedDetail_);
    DARABONBA_FROM_JSON(data, data_);
  }

public:
  Exception() = default;
  Exception(const Darabonba::Json &errorInfo) { from_json(errorInfo, *this); }

  const char *what() const noexcept override { return message_.c_str(); }

  int statusCode() const { return statusCode_; }
  Exception &setStatusCode(int statusCode) {
    DARABONBA_SET_VALUE(statusCode_, statusCode);
  }

  const std::string &code() const { return code_; }
  Exception &setCode(const std::string &code) {
    DARABONBA_SET_VALUE(code_, code);
  }
  Exception &setCode(std::string &&code) { DARABONBA_SET_RVALUE(code_, code); }

  const std::string &message() const { return message_; }
  Exception &setMessage(const std::string &message) {
    DARABONBA_SET_VALUE(message_, message);
  }
  Exception &setMessage(std::string &&message) {
    DARABONBA_SET_RVALUE(message_, message);
  }

  const std::string &description() const { return description_; }
  Exception &setDescription(const std::string &description) {
    DARABONBA_SET_VALUE(description_, description);
  }
  Exception &setDescription(std::string &&description) {
    DARABONBA_SET_RVALUE(description_, description);
  }

  const Darabonba::Json &accessDeniedDetail() const {
    return accessDeniedDetail_;
  }
  Exception &setAccessDeniedDetail(const Darabonba::Json &accessDeniedDetail) {
    DARABONBA_SET_VALUE(accessDeniedDetail_, accessDeniedDetail);
  }
  Exception &setAccessDeniedDetail(Darabonba::Json &&accessDeniedDetail) {
    DARABONBA_SET_RVALUE(accessDeniedDetail_, accessDeniedDetail);
  }

  const Darabonba::Json &data() const { return data_; }
  Exception &setData(const Darabonba::Json &data) {
    DARABONBA_SET_VALUE(data_, data);
  }
  Exception &setData(Darabonba::Json &&data) {
    DARABONBA_SET_RVALUE(data_, data);
  }

protected:
  int statusCode_;
  std::string code_;
  std::string message_;
  std::string description_;
  Darabonba::Json accessDeniedDetail_;
  Darabonba::Json data_;
};

class UnretryableException : public Darabonba::Exception {
public:
  UnretryableException() = default;
  UnretryableException(const Darabonba::Http::Request &lastRequest,
                       const OpenApi::Exception &lastException = {})
      : lastRequest_(lastRequest), lastException_(lastException) {}

  UnretryableException(const OpenApi::Exception &lastException)
      : lastException_(lastException) {}

  const Darabonba::Http::Request &lastRequest() const { return lastRequest_; }
  const Exception &lLastException() const { return lastException_; }

  const char *what() const noexcept override { return lastException_.what(); }

protected:
  Darabonba::Http::Request lastRequest_;
  OpenApi::Exception lastException_;
};

} // namespace OpenApi
} // namespace Alibabacloud
#endif