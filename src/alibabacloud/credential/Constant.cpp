#include <alibabacloud/credential/Constant.hpp>
namespace Alibabacloud {
namespace Credential {

const std::string Constant::SYSTEM_ACCESSKEYID = "alibabacloud.accessKeyId";
const std::string Constant::SYSTEM_ACCESSKEYSECRET =
    "alibabacloud.accessKeyIdSecret";
// const std::string Constant::DEFAULT_CREDENTIALS_FILE_PATH =
// System.getProperty("user.home") + "/.alibabacloud/credentials.ini";

const std::string Constant::INI_ACCESS_KEY_ID = "access_key_id";
const std::string Constant::INI_ACCESS_KEY_IDSECRET = "access_key_secret";
const std::string Constant::INI_TYPE = "type";
const std::string Constant::INI_TYPE_RAM = "ecs_ram_role";
const std::string Constant::INI_TYPE_ARN = "ram_role_arn";
const std::string Constant::INI_TYPE_OIDC = "oidc_role_arn";
const std::string Constant::INI_TYPE_KEY_PAIR = "rsa_key_pair";
const std::string Constant::INI_PUBLIC_KEY_ID = "public_key_id";
const std::string Constant::INI_PRIVATE_KEY_FILE = "private_key_file";
const std::string Constant::INI_PRIVATE_KEY = "private_key";
const std::string Constant::INI_ROLE_NAME = "role_name";
const std::string Constant::INI_ROLE_SESSION_NAME = "role_session_name";
const std::string Constant::INI_ROLE_ARN = "role_arn";
const std::string Constant::INI_POLICY = "policy";
const std::string Constant::INI_OIDC_PROVIDER_ARN = "oidc_provider_arn";
const std::string Constant::INI_OIDC_TOKEN_FILE_PATH = "oidc_token_file_path";
const long Constant::TSC_VALID_TIME_SECONDS = 3600L;
const std::string Constant::DEFAULT_REGION = "region_id";
const std::string Constant::INI_ENABLE = "enable";

const std::string Constant::ACCESS_KEY = "access_key";
const std::string Constant::STS = "sts";
const std::string Constant::ECS_RAM_ROLE = "ecs_ram_role";
const std::string Constant::RAM_ROLE_ARN = "ram_role_arn";
const std::string Constant::RSA_KEY_PAIR = "rsa_key_pair";
const std::string Constant::BEARER = "bearer";
const std::string Constant::OIDC_ROLE_ARN = "oidc_role_arn";
const std::string Constant::URL_STS = "credentials_uri";
} // namespace Credential
} // namespace Alibabacloud
