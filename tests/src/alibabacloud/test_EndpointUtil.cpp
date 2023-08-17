#include <alibabacloud/EndpointUtil.hpp>
#include <darabonba/Type.hpp>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

using namespace Darabonba;
using namespace Alibabacloud;
using namespace std;

TEST(Alibabacloud_EndpointUtil, getEndpointRules) {
  EXPECT_EQ("cs.region.aliyuncs.com",
            EndpointUtil::getEndpointRules("cs", "region", "regional", "", ""));
  EXPECT_EQ(
      "cs-suffix-test.aliyuncs.com",
      EndpointUtil::getEndpointRules("cs", "test", "public", "test", "suffix"));

  try {
    EndpointUtil::getEndpointRules("regional", "", "regional", "cs", "");
  } catch (Exception e) {
    EXPECT_EQ("RegionId is empty, please set a valid RegionId", std::string(e.what()));
  }
}
