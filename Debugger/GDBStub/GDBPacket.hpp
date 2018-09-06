//
// Created by Spencer Michaels on 9/5/18.
//

#ifndef XENDBG_GDBPACKET_HPP
#define XENDBG_GDBPACKET_HPP

#include <sstream>
#include <string>

namespace xd::dbg::gdbstub::pkt {

  class GDBPacket {
  public:
    virtual ~GDBPacket() = default;
    virtual std::string to_string() = 0;
  };

  class OK : public GDBPacket {
  public:
    std::string to_string() override { return "OK"; };
  };

  class NotSupported : public GDBPacket {
  public:
    std::string to_string() override { return ""; };
  };

  class Error : public GDBPacket {
  public:
    Error(uint8_t error_code)
      : _error_code(error_code) {};

    std::string to_string() override {
      std::stringstream ss;
      ss << "E" << std::hex << _error_code;
      return ss.str();
    };

  private:
    uint8_t _error_code;
  };

}

#endif //XENDBG_GDBPACKET_HPP
