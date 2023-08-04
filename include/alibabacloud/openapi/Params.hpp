#ifndef ALIBABACLOUD_OPENAPI_PARAMS_H_
#define ALIBABACLOUD_OPENAPI_PARAMS_H_

#include <darabonba/Model.hpp>

namespace Alibabacloud {
namespace OpenApi {

class Params : public Darabonba::Model {
  friend void to_json(Darabonba::Json &j, const Params &obj) {
    DARABONBA_PTR_TO_JSON(action, action_);
    DARABONBA_PTR_TO_JSON(authType, authType_);
    DARABONBA_PTR_TO_JSON(bodyType, bodyType_);
    DARABONBA_PTR_TO_JSON(method, method_);
    DARABONBA_PTR_TO_JSON(pathname, pathname_);
    DARABONBA_PTR_TO_JSON(protocol, protocol_);
    DARABONBA_PTR_TO_JSON(reqBodyType, reqBodyType_);
    DARABONBA_PTR_TO_JSON(style, style_);
    DARABONBA_PTR_TO_JSON(version, version_);
  }

  friend void from_json(const Darabonba::Json &j, Params &obj) {
    DARABONBA_PTR_FROM_JSON(action, action_);
    DARABONBA_PTR_FROM_JSON(authType, authType_);
    DARABONBA_PTR_FROM_JSON(bodyType, bodyType_);
    DARABONBA_PTR_FROM_JSON(method, method_);
    DARABONBA_PTR_FROM_JSON(pathname, pathname_);
    DARABONBA_PTR_FROM_JSON(protocol, protocol_);
    DARABONBA_PTR_FROM_JSON(reqBodyType, reqBodyType_);
    DARABONBA_PTR_FROM_JSON(style, style_);
    DARABONBA_PTR_FROM_JSON(version, version_);
  }

public:
  Params() = default;
  Params(const Params &) = default;
  Params(Params &&) = default;
  Params(const Darabonba::Json &obj) { from_json(obj, *this); }

  virtual ~Params() = default;

  Params &operator=(const Params &) = default;
  Params &operator=(Params &&) = default;

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
    return action_ == nullptr && authType_ == nullptr && bodyType_ == nullptr &&
           method_ == nullptr && pathname_ == nullptr && protocol_ == nullptr &&
           reqBodyType_ == nullptr && style_ == nullptr && version_ == nullptr;
  }

  bool hasAction() const { return this->action_ != nullptr; }
  std::string action() const { DARABONBA_PTR_GET_DEFAULT(action_, ""); }
  Params &setAction(const std::string &action) {
    DARABONBA_PTR_SET_VALUE(action_, action);
  }
  Params &setAction(std::string &&action) {
    DARABONBA_PTR_SET_RVALUE(action_, action);
  }

  bool hasAuthType() const { return this->authType_ != nullptr; }
  std::string authType() const { DARABONBA_PTR_GET_DEFAULT(authType_, ""); }
  Params &setAuthType(const std::string &authType) {
    DARABONBA_PTR_SET_VALUE(authType_, authType);
  }
  Params &setAuthType(std::string &&authType) {
    DARABONBA_PTR_SET_RVALUE(authType_, authType);
  }

  bool hasBodyType() const { return this->bodyType_ != nullptr; }
  std::string bodyType() const { DARABONBA_PTR_GET_DEFAULT(bodyType_, ""); }
  Params &setBodyType(const std::string &bodyType) {
    DARABONBA_PTR_SET_VALUE(bodyType_, bodyType);
  }
  Params &setBodyType(std::string &&bodyType) {
    DARABONBA_PTR_SET_RVALUE(bodyType_, bodyType);
  }

  bool hasMethod() const { return this->method_ != nullptr; }
  std::string method() const { DARABONBA_PTR_GET_DEFAULT(method_, ""); }
  Params &setMethod(const std::string &method) {
    DARABONBA_PTR_SET_VALUE(method_, method);
  }
  Params &setMethod(std::string &&method) {
    DARABONBA_PTR_SET_RVALUE(method_, method);
  }

  bool hasPathname() const { return this->pathname_ != nullptr; }
  std::string pathname() const { DARABONBA_PTR_GET_DEFAULT(pathname_, ""); }
  Params &setPathname(const std::string &pathname) {
    DARABONBA_PTR_SET_VALUE(pathname_, pathname);
  }
  Params &setPathname(std::string &&pathname) {
    DARABONBA_PTR_SET_RVALUE(pathname_, pathname);
  }

  bool hasProtocol() const { return this->protocol_ != nullptr; }
  std::string protocol() const { DARABONBA_PTR_GET_DEFAULT(protocol_, ""); }
  Params &setProtocol(const std::string &protocol) {
    DARABONBA_PTR_SET_VALUE(protocol_, protocol);
  }
  Params &setProtocol(std::string &&protocol) {
    DARABONBA_PTR_SET_RVALUE(protocol_, protocol);
  }

  bool hasReqBodyType() const { return this->reqBodyType_ != nullptr; }
  std::string reqBodyType() const {
    DARABONBA_PTR_GET_DEFAULT(reqBodyType_, "");
  }
  Params &setReqBodyType(const std::string &reqBodyType) {
    DARABONBA_PTR_SET_VALUE(reqBodyType_, reqBodyType);
  }
  Params &setReqBodyType(std::string &&reqBodyType) {
    DARABONBA_PTR_SET_RVALUE(reqBodyType_, reqBodyType);
  }

  bool hasStyle() const { return this->style_ != nullptr; }
  std::string style() const { DARABONBA_PTR_GET_DEFAULT(style_, ""); }
  Params &setStyle(const std::string &style) {
    DARABONBA_PTR_SET_VALUE(style_, style);
  }
  Params &setStyle(std::string &&style) {
    DARABONBA_PTR_SET_RVALUE(style_, style);
  }

  bool hasVersion() const { return this->version_ != nullptr; }
  std::string version() const { DARABONBA_PTR_GET_DEFAULT(version_, ""); }
  Params &setVersion(const std::string &version) {
    DARABONBA_PTR_SET_VALUE(version_, version);
  }
  Params &setVersion(std::string &&version) {
    DARABONBA_PTR_SET_RVALUE(version_, version);
  }

protected:
  std::shared_ptr<std::string> action_ = nullptr;
  std::shared_ptr<std::string> authType_ = nullptr;
  std::shared_ptr<std::string> bodyType_ = nullptr;
  std::shared_ptr<std::string> method_ = nullptr;
  std::shared_ptr<std::string> pathname_ = nullptr;
  std::shared_ptr<std::string> protocol_ = nullptr;
  std::shared_ptr<std::string> reqBodyType_ = nullptr;
  std::shared_ptr<std::string> style_ = nullptr;
  std::shared_ptr<std::string> version_ = nullptr;
};

} // namespace OpenApi
} // namespace Alibabacloud

#endif