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

#ifndef XENDBG_GDBREQUESTPACKET_HPP
#define XENDBG_GDBREQUESTPACKET_HPP

#include <iostream>
#include <optional>
#include <queue>
#include <sstream>
#include <stdexcept>
#include <string>
#include <variant>
#include <vector>

#include "GDBRequestBase.hpp"
#include "GDBBreakpointRequest.hpp"
#include "GDBMemoryRequest.hpp"
#include "GDBQueryRequest.hpp"
#include "GDBRegisterRequest.hpp"
#include "GDBStepContinueRequest.hpp"

#include <Registers/RegistersX86Any.hpp>
#include <Util/overloaded.hpp>

namespace xd::gdb::req {

  DECLARE_SIMPLE_REQUEST(InterruptRequest, '\x03');
  DECLARE_SIMPLE_REQUEST(StopReasonRequest, '?');
  DECLARE_SIMPLE_REQUEST(KillRequest, 'k');
  DECLARE_SIMPLE_REQUEST(StartNoAckModeRequest, "QStartNoAckMode");

  class RestartRequest : public GDBRequestBase {
  public:
    explicit RestartRequest(const std::string &data)
      : GDBRequestBase(data, 'R')
    {
      read_byte(); // Required, but ignored
      expect_end();
    };
  };

  class DetachRequest : public GDBRequestBase {
  public:
    explicit DetachRequest(const std::string &data)
      : GDBRequestBase(data, 'D'), _pid(0)
    {
      if (has_more()) {
        expect_char(';');
        _pid = read_hex_number<size_t>();
      }
      expect_end();
    };

    size_t get_pid() { return _pid; };

  private:
    size_t _pid;
  };

  class SetThreadRequest : public GDBRequestBase {
  public:
    explicit SetThreadRequest(const std::string &data)
      : GDBRequestBase(data, 'H')
    {
      if (check_char('c'))
        _op = Op::StepAndContinue;
      else if (check_char('g'))
        _op = Op::StepAndContinue;

      _thread_id = read_hex_number<size_t>();
      expect_end();
    };

    enum class Op {
      StepAndContinue,
      General,
    };

    Op get_op() const { return _op; }
    size_t get_thread_id() const { return _thread_id; }

  private:
    Op _op;
    size_t _thread_id;
  };

  using GDBRequest = std::variant<
    StartNoAckModeRequest,
    InterruptRequest,
    QueryWatchpointSupportInfo,
    QuerySupportedRequest,
    QueryEnableErrorStrings,
    QueryThreadSuffixSupportedRequest,
    QueryListThreadsInStopReplySupportedRequest,
    QueryCurrentThreadIDRequest,
    QueryThreadInfoStartRequest,
    QueryThreadInfoContinuingRequest,
    QueryHostInfoRequest,
    QueryProcessInfoRequest,
    QueryRegisterInfoRequest,
    QueryMemoryRegionInfoRequest,
    StopReasonRequest,
    KillRequest,
    SetThreadRequest,
    RegisterReadRequest,
    RegisterWriteRequest,
    GeneralRegistersBatchReadRequest,
    GeneralRegistersBatchWriteRequest,
    MemoryReadRequest,
    MemoryWriteRequest,
    ContinueRequest,
    ContinueSignalRequest,
    StepRequest,
    StepSignalRequest,
    BreakpointInsertRequest,
    BreakpointRemoveRequest,
    RestartRequest,
    DetachRequest>;

}

#endif //XENDBG_GDBREQUESTPACKET_HPP
