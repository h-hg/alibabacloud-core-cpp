#ifndef ALIBABACLOUD_GLOBALPARAMETERS_H_
#define ALIBABACLOUD_GLOBALPARAMETERS_H_

#include <darabonba/Model.hpp>
#include <darabonba/http/Header.hpp>
#include <darabonba/http/Query.hpp>
namespace Alibabacloud {
namespace OpenApi {

class GlobalParameters : public Darabonba::Model {
  friend void to_json(Darabonba::Json &j, const GlobalParameters &obj) {
    DARABONBA_PTR_TO_JSON(headers, headers_);
    DARABONBA_PTR_TO_JSON(queries, queries_);
  }

  friend void from_json(const Darabonba::Json &j, GlobalParameters &obj) {
    DARABONBA_PTR_FROM_JSON(headers, headers_);
    DARABONBA_PTR_FROM_JSON(queries, queries_);
  }

public:
  GlobalParameters() = default;
  GlobalParameters(const GlobalParameters &) = default;
  GlobalParameters(GlobalParameters &&) = default;
  GlobalParameters(const Darabonba::Json &obj) { from_json(obj, *this); }

  virtual ~GlobalParameters() = default;

  GlobalParameters &operator=(const GlobalParameters &) = default;
  GlobalParameters &operator=(GlobalParameters &&) = default;

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
    return headers_ == nullptr && queries_ == nullptr;
  }

  bool hasHeaders() const { return this->headers_ != nullptr; }
  const Darabonba::Http::Header &headers() const {
    DARABONBA_PTR_GET(headers_);
  }
  Darabonba::Http::Header &headers() { DARABONBA_PTR_GET(headers_); }
  GlobalParameters &setHeaders(const Darabonba::Http::Header &headers) {
    DARABONBA_PTR_SET_VALUE(headers_, headers);
  }
  GlobalParameters &setHeaders(Darabonba::Http::Header &&headers) {
    DARABONBA_PTR_SET_RVALUE(headers_, headers);
  }

  bool hasQueries() const { return this->queries_ != nullptr; }
  const Darabonba::Http::Query &queries() const { DARABONBA_PTR_GET(queries_); }
  Darabonba::Http::Query &queries() { DARABONBA_PTR_GET(queries_); }
  GlobalParameters &setQueries(const Darabonba::Http::Query &queries) {
    DARABONBA_PTR_SET_VALUE(queries_, queries);
  }
  GlobalParameters &setQueries(Darabonba::Http::Query &&queries) {
    DARABONBA_PTR_SET_RVALUE(queries_, queries);
  }

protected:
  std::shared_ptr<Darabonba::Http::Header> headers_ = nullptr;
  std::shared_ptr<Darabonba::Http::Query> queries_ = nullptr;
};

} // namespace OpenApi
} // namespace Alibabacloud
#endif
