//
// Created by Spencer Michaels on 10/1/18.
//

#ifndef XENDBG_GDBQUERYREQUEST_HPP
#define XENDBG_GDBQUERYREQUEST_HPP

#include <vector>

#include "GDBRequestBase.hpp"

namespace xd::gdb::req {

  DECLARE_SIMPLE_REQUEST(QueryEnableErrorStrings, "QEnableErrorStrings");

  DECLARE_SIMPLE_REQUEST(QueryThreadSuffixSupportedRequest, "QThreadSuffixSupported");

  DECLARE_SIMPLE_REQUEST(QueryListThreadsInStopReplySupportedRequest, "QListThreadsInStopReply");

  DECLARE_SIMPLE_REQUEST(QueryHostInfoRequest, "qHostInfo");

  DECLARE_SIMPLE_REQUEST(QueryProcessInfoRequest, "qProcessInfo");

  DECLARE_SIMPLE_REQUEST(QueryCurrentThreadIDRequest, "qC");

  DECLARE_SIMPLE_REQUEST(QueryThreadInfoStartRequest, "qfThreadInfo");

  DECLARE_SIMPLE_REQUEST(QueryThreadInfoContinuingRequest, "qsThreadInfo");

  class QuerySupportedRequest : public GDBRequestBase {
  public:
    explicit QuerySupportedRequest(const std::string &data);

    const std::vector<std::string> get_features() { return _features; };

  private:
    std::vector<std::string> _features;
  };

  class QueryRegisterInfoRequest : public GDBRequestBase {
  public:
    explicit QueryRegisterInfoRequest(const std::string &data);

    uint16_t get_register_id() const { return _register_id; };

  private:
    uint16_t _register_id;
  };

  class QueryMemoryRegionInfoRequest : public GDBRequestBase {
  public:
    explicit QueryMemoryRegionInfoRequest(const std::string &data);

    uint64_t get_address() const { return _address; };

  private:
    uint64_t _address;
  };

}

#endif //XENDBG_GDBQUERYREQUEST_HPP
