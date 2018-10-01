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

  class QuerySupportedRequest : public GDBRequestBase {
  public:
    explicit QuerySupportedRequest(const std::string &data)
      : GDBRequestBase(data, "qSupported")
    {
      expect_char(':');
      while (has_more()) {
        const auto feature = read_until_char_or_end(';');
        _features.push_back(feature);
      }
      expect_end();
    };

    const std::vector<std::string> get_features() { return _features; };

  private:
    std::vector<std::string> _features;
  };

  class QueryCurrentThreadIDRequest : public GDBRequestBase {
  public:
    explicit QueryCurrentThreadIDRequest(const std::string &data)
      : GDBRequestBase(data, "qC")
    {
      expect_end();
    };
  };

  class QueryThreadInfoStartRequest : public GDBRequestBase {
  public:
    explicit QueryThreadInfoStartRequest(const std::string &data)
      : GDBRequestBase(data, "qfThreadInfo")
    {
      expect_end();
    };
  };

  class QueryThreadInfoContinuingRequest : public GDBRequestBase {
  public:
    explicit QueryThreadInfoContinuingRequest(const std::string &data)
      : GDBRequestBase(data, "qsThreadInfo")
    {
      expect_end();
    };
  };

  class QueryRegisterInfoRequest : public GDBRequestBase {
  public:
    explicit QueryRegisterInfoRequest(const std::string &data)
      : GDBRequestBase(data, "qRegisterInfo")
    {
      _register_id = read_hex_number<uint16_t>();
      expect_end();
    };

    uint16_t get_register_id() const { return _register_id; };

  private:
    uint16_t _register_id;
  };

  class QueryMemoryRegionInfoRequest : public GDBRequestBase {
  public:
    QueryMemoryRegionInfoRequest(const std::string &data)
      : GDBRequestBase(data, "qMemoryRegionInfo")
    {
      expect_char(':');
      _address = read_hex_number<uint64_t>();
      expect_end();
    };

    uint64_t get_address() const { return _address; };

  private:
    uint64_t _address;
  };

}

#endif //XENDBG_GDBQUERYREQUEST_HPP
