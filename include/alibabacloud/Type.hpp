#ifndef ALIBABACLOUD_CODE_H_
#define ALIBABACLOUD_CODE_H_

#include <darabonba/Model.hpp>
#include <darabonba/Type.hpp>
#include <darabonba/http/Request.hpp>
#include <string>

// todo：这个应该放到 alibabacloud exception

namespace Alibabacloud {

// TODO 这个类过于复杂，应该简化一下

// class Exception : public std::exception {

//   friend void to_json(Darabonba::Json &j, const Exception &obj) {
//     DARABONBA_TO_JSON(code, code_);
//     DARABONBA_TO_JSON(message, message_);
//     DARABONBA_TO_JSON(data, data_);
//     DARABONBA_TO_JSON(description, description_);
//     DARABONBA_TO_JSON(accessDeniedDetail, accessDeniedDetail_);
//     // DARABONBA_TO_JSON(statusCode, statusCode_);
//   }
//   friend void from_json(const Darabonba::Json &j, Exception &obj) {
//     DARABONBA_FROM_JSON(code, code_);
//     DARABONBA_FROM_JSON(message, message_);
//     DARABONBA_FROM_JSON(data, data_);
//     DARABONBA_FROM_JSON(description, description_);
//     DARABONBA_FROM_JSON(accessDeniedDetail, accessDeniedDetail_);
//     if (j.count("data") && j["data"].count("statusCode")) {
//       obj.statusCode_ = j["data"]["statusCode"];
//     }
//   }

// public:
//   Exception() = default;
//   Exception(const Darabonba::Json &errorInfo) { from_json(errorInfo, *this);
//   }

//   const char *what() const noexcept override { return message_.c_str(); }

//   const std::string &code() const { return code_; }
//   void setCode(const std::string &code) { code_ = code; }

//   const std::string &message() const { return message_; }
//   void setMessage(const std::string &message) { message_ = message; }

//   const Darabonba::Json &data() const { return data_; }
//   void setData(const Darabonba::Json &data) { data_ = data; }

//   int statusCode() const { return statusCode_; }
//   void setStatusCode(int statusCode) { statusCode_ = statusCode; }

//   const std::string &description() const { return description_; }
//   void setDescription(const std::string &description) {
//     description_ = description;
//   }

//   const Darabonba::Json &accessDeniedDetail() const {
//     return accessDeniedDetail_;
//   }
//   void setAccessDeniedDetail(const Darabonba::Json &accessDeniedDetail) {
//     accessDeniedDetail_ = accessDeniedDetail;
//   }

// protected:
//   std::string code_;
//   std::string message_;
//   Darabonba::Json data_;
//   // TODO:
//   int statusCode_;
//   std::string description_;
//   Darabonba::Json accessDeniedDetail_;
// };

class Exception : public Darabonba::Exception {
public:
  Exception() = default;
  Exception(const Darabonba::Json &data) : data_(data) {}
  Exception(Darabonba::Json &&data) : data_(std::move(data)) {}

  virtual const char *what() const noexcept override {
    if (data_.is_string()) {
      strData_ = data_.get<std::string>();
    } else {
      strData_ = data_.dump();
    }
    return strData_.c_str();
  }

  const Darabonba::Json &data() const { return data_; }
  Darabonba::Json &data() { return data_; }

protected:
  Darabonba::Json data_;

  // Store the serialized data
  mutable std::string strData_;
};

class UnretryableException : public Exception {
public:
  UnretryableException() = default;
  UnretryableException(const Darabonba::Http::Request &lastRequest,
                       const Exception &lastException = {})
      : lastRequest_(lastRequest), lastException_(lastException) {}

  UnretryableException(const Exception &lastException)
      : lastException_(lastException) {}

  const Darabonba::Http::Request &lastRequest() const { return lastRequest_; }
  const Exception &lLastException() const { return lastException_; }

protected:
  Darabonba::Http::Request lastRequest_;
  Exception lastException_;
};

class RetryableException : public Exception {
public:
  RetryableException() = default;
  RetryableException(const Darabonba::Json &errorInfo) : Exception(errorInfo){};
};

} // namespace Alibabacloud
#endif