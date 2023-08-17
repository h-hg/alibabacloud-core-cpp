#include <alibabacloud/openapi/Util.hpp>
#include <darabonba/Type.hpp>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <iostream>

using namespace Darabonba;
using namespace Alibabacloud;
using namespace Alibabacloud::OpenApi;
using namespace std;

TEST(Alibabacloud_OpenApi_Util, convert) {
  // TODO
}
TEST(Alibabacloud_OpenApi_Util, getStringToSign) {
  EXPECT_EQ(Util::getStringToSign(Darabonba::Http::Request()), "GET\n\n\n\n\n");
  Darabonba::Http::Request req2;
  req2.setMethod("POST");
  req2.setQuery({{"test", "tests"}});
  EXPECT_EQ(Util::getStringToSign(req2), "POST\n\n\n\n\n?test=tests");
  Darabonba::Http::Request req3;
  map<string, string> reqMap = {
      {"x-acs-security-token", "test"},
      {"x-acs-security-test", "test"},
      {"accept", "accept"},
      {"content-md5", "content-md5"},
      {"content-type", "content-type"},
      {"date", "date"},
      {"chineseTest", "汉语"},
      {"emptyTest", ""},
      {"spaceTest", "   "},
  };
  req3.setHeader(reqMap);
  req3.setQuery(reqMap);
  req3.url().setPathName("/test");
  EXPECT_EQ(Util::getStringToSign(req3),
            "GET\n"
            "accept\n"
            "content-md5\n"
            "content-type\n"
            "date\n"
            "x-acs-security-test:test\n"
            "x-acs-security-token:test\n"
            "/test?accept=accept&chineseTest=汉语&content-md5=content-md5&"
            "content-type=content-type&date=date&"
            "emptyTest&spaceTest=   "
            "&x-acs-security-test=test&x-acs-security-token=test");
}

TEST(Alibabacloud_OpenApi_Util, getROASignature) {
  EXPECT_EQ("XGXDWA78AEvx/wmfxKoVCq/afWw=",
            Util::getROASignature(
                Util::getStringToSign(Darabonba::Http::Request()), "secret"));
}

TEST(Alibabacloud_OpenApi_Util, toForm) {
  Darabonba::Json filter = {{"client", "test"},
                            {"client1", nullptr},
                            {"strs", Darabonba::Json::array({"str1", "str2"})},
                            {"tag",
                             {
                                 {"key", "value"},
                             }}};

  EXPECT_EQ("client=test&strs.1=str1&strs.2=str2&tag.key=value",
            Util::toForm(filter));
}

TEST(Alibabacloud_OpenApi_Util, getTimestamp) {
  auto s = Util::getTimestamp();
  EXPECT_TRUE(s.find('T') != string::npos);
  EXPECT_TRUE(s.find('Z') != string::npos);
}

TEST(Alibabacloud_OpenApi_Util, query) {
  EXPECT_EQ(Util::query(nullptr).size(), 0);
  auto ans2 = map<string, string>{{"str_test", "test"}, {"int_test", "1"}};
  EXPECT_EQ(
      Util::query(
          {{"str_test", "test"}, {"none_test", nullptr}, {"int_test", 1}}),
      ans2);
  auto ans3 = map<string, string>{{"int_test", "1"},
                                  {"list_test.1", "1"},
                                  {"list_test.3.str_test", "test"},
                                  {"str_test", "test"}};
  EXPECT_EQ(
      Util::query(Json{
          {"str_test", "test"},
          {"none_test", nullptr},
          {"int_test", 1},
          {"list_test",
           Json::array({1, nullptr, Json::object({{"str_test", "test"}})})}}),
      ans3);
  // TODO Darabonba::Model
}

TEST(Alibabacloud_OpenApi_Util, getRPCSignature) {
  EXPECT_EQ(Util::getRPCSignature({{"query", "test"}, {"body", "test"}}, "GET",
                                  "secret"),
            "XlUyV4sXjOuX5FnjUz9IF9tm5rU=");
}

TEST(Alibabacloud_OpenApi_Util, arrayToStringWithSpecifiedStyle) {
  auto array = Json::array({"ok", "test", 2, 3});
  string prefix = "instance";
  Util::arrayToStringWithSpecifiedStyle(array, prefix, "repeatList");
  EXPECT_EQ("instance.1=ok&&instance.2=test&&instance.3=2&&instance.4=3",
            Util::arrayToStringWithSpecifiedStyle(array, prefix, "repeatList"));
  EXPECT_EQ(R"(["ok","test",2,3])",
            Util::arrayToStringWithSpecifiedStyle(array, prefix, "json"));
  EXPECT_EQ("ok,test,2,3",
            Util::arrayToStringWithSpecifiedStyle(array, prefix, "simple"));
  EXPECT_EQ("ok test 2 3", Util::arrayToStringWithSpecifiedStyle(
                               array, prefix, "spaceDelimited"));
  EXPECT_EQ("ok|test|2|3", Util::arrayToStringWithSpecifiedStyle(
                               array, prefix, "pipeDelimited"));
  EXPECT_EQ(
      "", Util::arrayToStringWithSpecifiedStyle(array, prefix, "piDelimited"));
  EXPECT_EQ("", Util::arrayToStringWithSpecifiedStyle(nullptr, prefix,
                                                      "pipeDelimited"));
  // TODO Darbonba::Model
}

TEST(Alibabacloud_OpenApi_Util, parseToMap) {
  // Nothing
}

TEST(Alibabacloud_OpenApi_Util, getEndpoint) {
  EXPECT_EQ("cc-internal.abc.com",
            Util::getEndpoint("cc.abc.com", false, "internal"));

  EXPECT_EQ("oss-accelerate.aliyuncs.com",
            Util::getEndpoint("", true, "accelerate"));
  EXPECT_EQ("test", Util::getEndpoint("test", true, "test"));
}

TEST(Alibabacloud_OpenApi_Util, hash_and_hexEncode) {

  string rawStr = "test";
  Bytes rawBytes;
  rawBytes.assign(rawStr.begin(), rawStr.end());

  EXPECT_EQ(Util::hexEncode(Util::hash(rawBytes, "ACS3-HMAC-SHA256")),
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08");
  EXPECT_EQ(Util::hexEncode(Util::hash(rawBytes, "ACS3-RSA-SHA256")),
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08");
  EXPECT_EQ(Util::hexEncode(Util::hash(rawBytes, "ACS3-HMAC-SM3")),
            "55e12e91650d2fec56ec74e1d3e4ddbfce2ef3a65890c2a19ecf88a307e76a23");
  EXPECT_EQ(Util::hexEncode(Util::hash(rawBytes, "ACS3-SHA256")), "");
}

TEST(Alibabacloud_OpenApi_Util, getAuthorization) {

  Darabonba::Http::Request req;
  req.setQuery({
      {"test", "ok"},
      {"empty", ""},

  });
  req.setHeader({
      {"x-acs-test", "http"},
      {"x-acs-TEST", "https"},
  });

  EXPECT_EQ(
      "ACS3-HMAC-SHA256 "
      "Credential=acesskey,SignedHeaders=x-acs-test,Signature="
      "d16b30a7699ae9e43875b13195b2f81bcc3ed10c14a9b5eb780e51619aa50be1",
      Util::getAuthorization(
          req, "ACS3-HMAC-SHA256",
          "55e12e91650d2fec56ec74e1d3e4ddbfce2ef3a65890c2a19ecf88a307e76a23",
          "acesskey", "secret"));
}

TEST(Alibabacloud_OpenApi_Util, getEncodePath) {
  EXPECT_EQ(Util::getEncodePath("/path/ test"), "/path/%20test");
}

TEST(Alibabacloud_OpenApi_Util, getEncodeParam) {
  EXPECT_EQ(Util::getEncodeParam("a/b/c/ test"), "a%2Fb%2Fc%2F%20test");
}

TEST(Alibabacloud_OpenApi_Util, signatureMethod) {
  string priKey =
      "-----BEGIN RSA PRIVATE "
      "KEY-----"
      "\nMIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAKzSQmrnH0YnezZ9"
      "8NK50WjMuci0hgGVcSthIZOTWMIySznY9Jj1hlvek7W0uYagtFHz03BHQnHAb5Xs"
      "0DZm0Sj9+5r79GggwEzTJDYEsLyFwXM3ZOIxqxL4sRg94MHsa81M9NXGHMyMvvff"
      "QTn1OBVLTVz5jgJ48foMn7j7r9kRAgMBAAECgYEAnZppw3/ef2XF8Z3Mnv+iP0Zk"
      "LuqiQpN8TykXK7P1/7NJ8wktlshhrSo/3jdf8axghVQsgHob2Ay8Nidugg4lsxIL"
      "AUBHvfQsQp1MAWvxslsVj+ddw01MQnt8kHmC/qhok+YuNqqAGBcoD6cthRUjEri6"
      "hfs599EfPs2DcWW06qECQQDfNqUUhcDQ/SQHRhfY9UIlaSEs2CVagDrSYFG1wyG+"
      "PXDSMes9ZRHsvVVBmNGmtUTg/jioTU3yuPsis5s9ppbVAkEAxjTAQxv5lBBm/ikM"
      "TzPShljxDZnXh6lKWG9gR1p5fKoQTzLyyhHzkBSFe848sMm68HWCX2wgIpQLHj0G"
      "ccYPTQJAduMKBeY/jpBlkiI5LWtj8b0O2G2/Z3aI3ehDXQYzgLoEz0+bNbYRWAB3"
      "2lpkv+AocZW1455Y+ACichcrhiimiQJAW/6L5hoL4u8h/oFq1zAEXJrXdyqaYLrw"
      "aM947mVN0dDVNQ0+pw9h7tO3iNkWTi+zdnv0APociDASYPyOCyyUWQJACMNRM1/r"
      "boXuKfMmVjmmz0XhaDUC/JkqSwIiaZi+47M21e9BTp1218NA6VaPgJJHeJr4sNOn"
      "Ysx+1cwXO5cuZg==\n-----END RSA PRIVATE KEY-----";

  Util::hexEncode(Util::signatureMethod("", "secret", "ACS3-HMAC-SM3"));
  EXPECT_EQ(
      "71e9db0344cd62427ccb824234214e14a0a54fe80adfb46bd12453270961dd5b",
      Util::hexEncode(Util::signatureMethod("", "secret", "ACS3-HMAC-SM3")));

  EXPECT_EQ("b9ff646822f41ef647c1416fa2b8408923828abc0464af6706e18db3e8553da8",
            Util::hexEncode(
                Util::signatureMethod("source", "secret", "ACS3-HMAC-SM3")));

  Util::signatureMethod("source", priKey, "ACS3-RSA-SHA256");
  EXPECT_EQ(
      "a00b88ae04f651a8ab645e724949ff435bbb2cf9a37aa54323024477f8031f4e13dc9484"
      "84c5c5a81ba53a55eb0571dffccc1e953c93269d6da23ed319e0f1ef699bcc9823a64657"
      "4628ae1b70ed569b5a07d139dda28996b5b9231f5ba96141f0893deec2fbf54a0fa2c203"
      "b8ae74dd26f457ac29c873745a5b88273d2b3d12",
      Util::hexEncode(
          Util::signatureMethod("source", priKey, "ACS3-RSA-SHA256")));
}

TEST(Alibabacloud_OpenApi_Util, mapToFlatStyle) {
  // TODO
}
