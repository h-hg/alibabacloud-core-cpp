#ifndef ALIBABACLOUD_CREDENTIAL_CONFIG_H_
#define ALIBABACLOUD_CREDENTIAL_CONFIG_H_

#include <darabonba/Model.hpp>
#include <memory>

class Config : public Darabonba::Model {
  friend void to_json(Darabonba::JSON &j, const Config &obj) {
    DARABONBA_PTR_TO_JSON(accessKeyId, accessKeyId);
    DARABONBA_PTR_TO_JSON(accessKeySecret, accessKeySecret);
    DARABONBA_PTR_TO_JSON(securityToken, securityToken);
    DARABONBA_PTR_TO_JSON(bearerToken, bearerToken);
    DARABONBA_PTR_TO_JSON(durationSeconds, durationSeconds);
    DARABONBA_PTR_TO_JSON(roleArn, roleArn);
    DARABONBA_PTR_TO_JSON(policy, policy);
    DARABONBA_PTR_TO_JSON(roleSessionExpiration, roleSessionExpiration);
    DARABONBA_PTR_TO_JSON(roleSessionName, roleSessionName);
    DARABONBA_PTR_TO_JSON(publicKeyId, publicKeyId);
    DARABONBA_PTR_TO_JSON(privateKeyFile, privateKeyFile);
    DARABONBA_PTR_TO_JSON(roleName, roleName);
    DARABONBA_PTR_TO_JSON(type, type);
  }

  friend void from_json(const Darabonba::JSON &j, Config &obj) {
    DARABONBA_PTR_FROM_JSON(accessKeyId, accessKeyId);
    DARABONBA_PTR_FROM_JSON(accessKeySecret, accessKeySecret);
    DARABONBA_PTR_FROM_JSON(securityToken, securityToken);
    DARABONBA_PTR_FROM_JSON(bearerToken, bearerToken);
    DARABONBA_PTR_FROM_JSON(durationSeconds, durationSeconds);
    DARABONBA_PTR_FROM_JSON(roleArn, roleArn);
    DARABONBA_PTR_FROM_JSON(policy, policy);
    DARABONBA_PTR_FROM_JSON(roleSessionExpiration, roleSessionExpiration);
    DARABONBA_PTR_FROM_JSON(roleSessionName, roleSessionName);
    DARABONBA_PTR_FROM_JSON(publicKeyId, publicKeyId);
    DARABONBA_PTR_FROM_JSON(privateKeyFile, privateKeyFile);
    DARABONBA_PTR_FROM_JSON(roleName, roleName);
    DARABONBA_PTR_FROM_JSON(type, type);
  }

public:
  Config() {}
  explicit Config(Darabonba::JSON &config) { from_json(config, *this); };
  ~Config() = default;

  virtual void validate() const override {}

  virtual Darabonba::JSON toMap() const override {
    Darabonba::JSON map;
    to_json(map, *this);
    return map;
  }

  virtual void fromMap(const Darabonba::JSON &map) override {
    validate();
    from_json(map, *this);
  }

  std::shared_ptr<std::string> accessKeyId;
  std::shared_ptr<std::string> accessKeySecret;
  std::shared_ptr<std::string> securityToken;
  std::shared_ptr<std::string> bearerToken;
  std::shared_ptr<int> durationSeconds;
  std::shared_ptr<std::string> roleArn;
  std::shared_ptr<std::string> policy;
  std::shared_ptr<int> roleSessionExpiration;
  std::shared_ptr<std::string> roleSessionName;
  std::shared_ptr<std::string> publicKeyId;
  std::shared_ptr<std::string> privateKeyFile;
  std::shared_ptr<std::string> roleName;
  // todo: java 版本这里有个 default 值
  std::shared_ptr<std::string> type;
};

#endif