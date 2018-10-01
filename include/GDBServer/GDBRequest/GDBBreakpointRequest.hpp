//
// Created by Spencer Michaels on 10/1/18.
//

#ifndef XENDBG_GDBBREAKPOINTREQUEST_HPP
#define XENDBG_GDBBREAKPOINTREQUEST_HPP

#include "GDBRequestBase.hpp"

#define DECLARE_BREAKPOINT_REQUEST(name, ch) \
  class name : public GDBRequestBase { \
  public: \
    explicit name(const std::string &data) \
      : GDBRequestBase(data, ch) \
    { \
      _type = read_hex_number<uint8_t>(); \
      expect_char(','); \
      _address = read_hex_number<uint64_t>(); \
      expect_char(','); \
      _kind = read_hex_number<uint8_t>(); \
      expect_end(); \
    }; \
    uint64_t get_address() const { return _address; }; \
    uint8_t get_type() const { return _type; }; \
    uint8_t get_kind() const { return _kind; }; \
  private: \
    uint64_t _address; \
    uint8_t _type, _kind; \
  }

namespace xd::gdb::req {

  DECLARE_BREAKPOINT_REQUEST(BreakpointInsertRequest, 'Z');
  DECLARE_BREAKPOINT_REQUEST(BreakpointRemoveRequest, 'z');

}

#endif //XENDBG_GDBBREAKPOINTREQUEST_HPP
