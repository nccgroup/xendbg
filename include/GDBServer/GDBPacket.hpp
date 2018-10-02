//
// Created by Spencer Michaels on 10/2/18.
//

#ifndef XENDBG_GDBPACKET_HPP
#define XENDBG_GDBPACKET_HPP

#include <cstddef>
#include <string>

namespace xd::gdb {

  class GDBPacket {
  public:
    explicit GDBPacket(std::string contents);
    GDBPacket(std::string contents, uint8_t checksum);

    const std::string &get_contents() const { return _contents; };
    const uint8_t &get_checksum() const { return _checksum; };

    std::string to_string() const;

    bool is_checksum_valid() const;
    bool starts_with(const std::string &s) const;

  private:
    std::string _contents;
    uint8_t _checksum;

    uint8_t calculate_checksum() const;
  };

}

#endif //XENDBG_GDBPACKET_HPP
