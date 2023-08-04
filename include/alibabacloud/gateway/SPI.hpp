#ifndef ALIBABACLOUD_GATEWAP_SPI_H_
#define ALIBABACLOUD_GATEWAP_SPI_H_

#include <alibabacloud/gateway/AttributeMap.hpp>
#include <alibabacloud/gateway/InterceptorContext.hpp>
#include <memory>

namespace Alibabacloud {
namespace Gateway {
class SPI {
public:
  virtual ~SPI() {}
  virtual void modifyConfiguration(InterceptorContext &context,
                                   AttributeMap &attributeMap) = 0;

  virtual void modifyRequest(InterceptorContext &context,
                             AttributeMap &attributeMap) = 0;

  virtual void modifyResponse(InterceptorContext &context,
                              AttributeMap &attributeMap) = 0;
};

} // namespace Gateway
} // namespace Alibabacloud
#endif
