#ifndef ALIBABACLOUD_CREDENTIAL_CONFIG_H_
#define ALIBABACLOUD_CREDENTIAL_CONFIG_H_

#include <darabonba/Model.hpp>
#include <memory>

namespace Alibabacloud {
namespace Credential {

class Config : public Darabonba::Model {
  friend void to_json(Darabonba::Json &j, const Config &obj) {
    DARABONBA_PTR_TO_JSON(accessKeyId, accessKeyId_);
    DARABONBA_PTR_TO_JSON(accessKeySecret, accessKeySecret_);
    DARABONBA_PTR_TO_JSON(bearerToken, bearerToken_);
    DARABONBA_PTR_TO_JSON(durationSeconds, durationSeconds_);
    DARABONBA_PTR_TO_JSON(externalId, externalId_);
    DARABONBA_PTR_TO_JSON(policy, policy_);
    DARABONBA_PTR_TO_JSON(privateKeyFile, privateKeyFile_);
    DARABONBA_PTR_TO_JSON(publicKeyId, publicKeyId_);
    DARABONBA_PTR_TO_JSON(roleArn, roleArn_);
    DARABONBA_PTR_TO_JSON(roleName, roleName_);
    DARABONBA_PTR_TO_JSON(roleSessionExpiration, roleSessionExpiration_);
    DARABONBA_PTR_TO_JSON(roleSessionName, roleSessionName_);
    DARABONBA_PTR_TO_JSON(securityToken, securityToken_);
    DARABONBA_PTR_TO_JSON(stsEndpoint, stsEndpoint_);
    DARABONBA_PTR_TO_JSON(type, type_);
  }

  friend void from_json(const Darabonba::Json &j, Config &obj) {
    DARABONBA_PTR_FROM_JSON(accessKeyId, accessKeyId_);
    DARABONBA_PTR_FROM_JSON(accessKeySecret, accessKeySecret_);
    DARABONBA_PTR_FROM_JSON(bearerToken, bearerToken_);
    DARABONBA_PTR_FROM_JSON(durationSeconds, durationSeconds_);
    DARABONBA_PTR_FROM_JSON(externalId, externalId_);
    DARABONBA_PTR_FROM_JSON(policy, policy_);
    DARABONBA_PTR_FROM_JSON(privateKeyFile, privateKeyFile_);
    DARABONBA_PTR_FROM_JSON(publicKeyId, publicKeyId_);
    DARABONBA_PTR_FROM_JSON(roleArn, roleArn_);
    DARABONBA_PTR_FROM_JSON(roleName, roleName_);
    DARABONBA_PTR_FROM_JSON(roleSessionExpiration, roleSessionExpiration_);
    DARABONBA_PTR_FROM_JSON(roleSessionName, roleSessionName_);
    DARABONBA_PTR_FROM_JSON(securityToken, securityToken_);
    DARABONBA_PTR_FROM_JSON(stsEndpoint, stsEndpoint_);
    DARABONBA_PTR_FROM_JSON(type, type_);
  }

public:
  Config() = default;
  Config(const Config &) = default;
  Config(Config &&) = default;
  Config(const Darabonba::Json &obj) { from_json(obj, *this); }

  virtual ~Config() = default;

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
           bearerToken_ == nullptr && durationSeconds_ == nullptr &&
           externalId_ == nullptr && policy_ == nullptr &&
           privateKeyFile_ == nullptr && publicKeyId_ == nullptr &&
           roleArn_ == nullptr && roleName_ == nullptr &&
           roleSessionExpiration_ == nullptr && roleSessionName_ == nullptr &&
           securityToken_ == nullptr && stsEndpoint_ == nullptr &&
           type_ == nullptr;
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

  bool hasBearerToken() const { return this->bearerToken_ != nullptr; }
  std::string bearerToken() const {
    DARABONBA_PTR_GET_DEFAULT(bearerToken_, "");
  }
  Config &setBearerToken(const std::string &bearerToken) {
    DARABONBA_PTR_SET_VALUE(bearerToken_, bearerToken);
  }
  Config &setBearerToken(std::string &&bearerToken) {
    DARABONBA_PTR_SET_RVALUE(bearerToken_, bearerToken);
  }

  bool hasDurationSeconds() const { return this->durationSeconds_ != nullptr; }
  int64_t durationSeconds() const {
    DARABONBA_PTR_GET_DEFAULT(durationSeconds_, 0);
  }
  Config &setDurationSeconds(int64_t durationSeconds) {
    DARABONBA_PTR_SET_VALUE(durationSeconds_, durationSeconds);
  }

  bool hasExternalId() const { return this->externalId_ != nullptr; }
  std::string externalId() const { DARABONBA_PTR_GET_DEFAULT(externalId_, ""); }
  Config &setExternalId(const std::string &externalId) {
    DARABONBA_PTR_SET_VALUE(externalId_, externalId);
  }
  Config &setExternalId(std::string &&externalId) {
    DARABONBA_PTR_SET_RVALUE(externalId_, externalId);
  }

  bool hasPolicy() const { return this->policy_ != nullptr; }
  std::string policy() const { DARABONBA_PTR_GET_DEFAULT(policy_, ""); }
  Config &setPolicy(const std::string &policy) {
    DARABONBA_PTR_SET_VALUE(policy_, policy);
  }
  Config &setPolicy(std::string &&policy) {
    DARABONBA_PTR_SET_RVALUE(policy_, policy);
  }

  bool hasPrivateKeyFile() const { return this->privateKeyFile_ != nullptr; }
  std::string privateKeyFile() const {
    DARABONBA_PTR_GET_DEFAULT(privateKeyFile_, "");
  }
  Config &setPrivateKeyFile(const std::string &privateKeyFile) {
    DARABONBA_PTR_SET_VALUE(privateKeyFile_, privateKeyFile);
  }
  Config &setPrivateKeyFile(std::string &&privateKeyFile) {
    DARABONBA_PTR_SET_RVALUE(privateKeyFile_, privateKeyFile);
  }

  bool hasPublicKeyId() const { return this->publicKeyId_ != nullptr; }
  std::string publicKeyId() const {
    DARABONBA_PTR_GET_DEFAULT(publicKeyId_, "");
  }
  Config &setPublicKeyId(const std::string &publicKeyId) {
    DARABONBA_PTR_SET_VALUE(publicKeyId_, publicKeyId);
  }
  Config &setPublicKeyId(std::string &&publicKeyId) {
    DARABONBA_PTR_SET_RVALUE(publicKeyId_, publicKeyId);
  }

  bool hasRoleArn() const { return this->roleArn_ != nullptr; }
  std::string roleArn() const { DARABONBA_PTR_GET_DEFAULT(roleArn_, ""); }
  Config &setRoleArn(const std::string &roleArn) {
    DARABONBA_PTR_SET_VALUE(roleArn_, roleArn);
  }
  Config &setRoleArn(std::string &&roleArn) {
    DARABONBA_PTR_SET_RVALUE(roleArn_, roleArn);
  }

  bool hasRoleName() const { return this->roleName_ != nullptr; }
  std::string roleName() const { DARABONBA_PTR_GET_DEFAULT(roleName_, ""); }
  Config &setRoleName(const std::string &roleName) {
    DARABONBA_PTR_SET_VALUE(roleName_, roleName);
  }
  Config &setRoleName(std::string &&roleName) {
    DARABONBA_PTR_SET_RVALUE(roleName_, roleName);
  }

  bool hasRoleSessionExpiration() const {
    return this->roleSessionExpiration_ != nullptr;
  }
  int64_t roleSessionExpiration() const {
    DARABONBA_PTR_GET_DEFAULT(roleSessionExpiration_, 0);
  }
  Config &setRoleSessionExpiration(int64_t roleSessionExpiration) {
    DARABONBA_PTR_SET_VALUE(roleSessionExpiration_, roleSessionExpiration);
  }

  bool hasRoleSessionName() const { return this->roleSessionName_ != nullptr; }
  std::string roleSessionName() const {
    DARABONBA_PTR_GET_DEFAULT(roleSessionName_, "");
  }
  Config &setRoleSessionName(const std::string &roleSessionName) {
    DARABONBA_PTR_SET_VALUE(roleSessionName_, roleSessionName);
  }
  Config &setRoleSessionName(std::string &&roleSessionName) {
    DARABONBA_PTR_SET_RVALUE(roleSessionName_, roleSessionName);
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

  bool hasStsEndpoint() const { return this->stsEndpoint_ != nullptr; }
  std::string stsEndpoint() const {
    DARABONBA_PTR_GET_DEFAULT(stsEndpoint_, "");
  }
  Config &setStsEndpoint(const std::string &stsEndpoint) {
    DARABONBA_PTR_SET_VALUE(stsEndpoint_, stsEndpoint);
  }
  Config &setStsEndpoint(std::string &&stsEndpoint) {
    DARABONBA_PTR_SET_RVALUE(stsEndpoint_, stsEndpoint);
  }

  bool hasType() const { return this->type_ != nullptr; }
  std::string type() const { DARABONBA_PTR_GET_DEFAULT(type_, ""); }
  Config &setType(const std::string &type) {
    DARABONBA_PTR_SET_VALUE(type_, type);
  }
  Config &setType(std::string &&type) { DARABONBA_PTR_SET_RVALUE(type_, type); }

protected:
  std::shared_ptr<std::string> accessKeyId_ = nullptr;
  std::shared_ptr<std::string> accessKeySecret_ = nullptr;
  std::shared_ptr<std::string> bearerToken_ = nullptr;
  std::shared_ptr<int64_t> durationSeconds_ = nullptr;
  std::shared_ptr<std::string> externalId_ = nullptr;
  std::shared_ptr<std::string> policy_ = nullptr;
  std::shared_ptr<std::string> privateKeyFile_ = nullptr;
  std::shared_ptr<std::string> publicKeyId_ = nullptr;
  std::shared_ptr<std::string> roleArn_ = nullptr;
  std::shared_ptr<std::string> roleName_ = nullptr;
  std::shared_ptr<int64_t> roleSessionExpiration_ = nullptr;
  std::shared_ptr<std::string> roleSessionName_ = nullptr;
  std::shared_ptr<std::string> securityToken_ = nullptr;
  std::shared_ptr<std::string> stsEndpoint_ = nullptr;
  std::shared_ptr<std::string> type_ = nullptr;
};
} // namespace Credential
} // namespace Alibabacloud
#endif