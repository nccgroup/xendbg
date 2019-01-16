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

#ifndef XENDBG_GDBRESPONSEPACKET_HPP
#define XENDBG_GDBRESPONSEPACKET_HPP

#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <variant>
#include <vector>

#include <Xen/Common.hpp>
#include <Registers/RegistersX86Any.hpp>
#include <Util/overloaded.hpp>

#include "GDBMemoryResponse.hpp"
#include "GDBResponseBase.hpp"
#include "GDBQueryResponse.hpp"
#include "GDBRegisterResponse.hpp"

namespace xd::gdb::rsp {

  class OKResponse : public GDBResponse {
  public:
    std::string to_string() const override { return "OK"; };
  };

  class NotSupportedResponse : public GDBResponse {
  public:
    std::string to_string() const override { return ""; };
  };

  class ErrorResponse : public GDBResponse {
  public:
    explicit ErrorResponse(uint8_t error_code)
      : _error_code(error_code) {};
    ErrorResponse(uint8_t error_code, std::string message)
      : _error_code(error_code), _message(std::move(message)) {};

    std::string to_string() const override;

  private:
    uint8_t _error_code;
    std::string _message;
  };

  class StopReasonSignalResponse : public GDBResponse {
  public:
    StopReasonSignalResponse(uint8_t signal, size_t thread_id, std::vector<size_t> thread_ids)
      : _signal(signal), _thread_id(thread_id), _thread_ids(std::move(thread_ids)),
        _stop_reason_key(""), _stop_reason_value("")
    {};

    StopReasonSignalResponse(uint8_t signal, size_t thread_id, std::vector<size_t> thread_ids,
        std::string stop_reason_key, std::string stop_reason_value)
      : _signal(signal), _thread_id(thread_id), _thread_ids(std::move(thread_ids)),
        _stop_reason_key(std::move(stop_reason_key)),
        _stop_reason_value(std::move(stop_reason_value))
    {};

    std::string to_string() const override;

  private:
    uint8_t _signal;
    size_t _thread_id;
    std::vector<size_t> _thread_ids;
    std::string _stop_reason_key, _stop_reason_value;
  };

  class TerminatedResponse : public GDBResponse {
  public:
    explicit TerminatedResponse(uint8_t signal)
      : _signal(signal) {};

    std::string to_string() const override {
      std::stringstream ss;
      ss << "X";
      write_byte(ss, _signal);
      return ss.str();
    };

  private:
    uint8_t _signal;
    size_t _thread_id;
  };

}

#endif //XENDBG_GDBRESPONSEPACKET_HPP
