//
// Copyright (C) 2018-2019 NCC Group
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
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

  class QueryWatchpointSupportInfo : public GDBRequestBase {
  public:
    explicit QueryWatchpointSupportInfo(const std::string &data);
  };

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
