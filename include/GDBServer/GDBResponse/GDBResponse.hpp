//
// Created by Spencer Michaels on 9/5/18.
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
