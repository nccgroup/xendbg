//
// Created by Spencer Michaels on 10/1/18.
//

#ifndef XENDBG_GDBRESPONSEBASE_HPP
#define XENDBG_GDBRESPONSEBASE_HPP

#include <iomanip>
#include <sstream>
#include <string>

namespace xd::gdb::rsp {

  namespace {
    // Writes the bytes of a value of arbitrary size in guest order
    template <typename Value_t>
    void write_bytes(std::stringstream &ss, Value_t value) {
      auto *p = (unsigned char*)&value;
      auto *end = p + sizeof(Value_t);

      ss << std::hex << std::setfill('0');
      while (p != end)
        ss << std::setw(2) << (unsigned)(*p++);
    }

    void write_byte(std::stringstream &ss, uint8_t byte) {
      ss << std::hex << std::setfill('0');
      ss << std::setw(2) << (unsigned)byte;
    }

    std::string hexify(const std::string& s) {
      std::stringstream ss;
      ss << std::hex << std::setfill('0');
      for (const unsigned char c : s)
        ss << std::setw(2) << (unsigned)c;
      return ss.str();
    }

    template <typename Value_t>
    void add_list_entry(std::stringstream &ss, Value_t value) {
      ss << value;
      ss << ",";
    }

    template <typename Key_t, typename Value_t>
    void add_map_entry(std::stringstream &ss, Key_t key, Value_t value) {
      ss << key;
      ss << ":";
      ss << value;
      ss << ";";
    }
  }

  class GDBResponse {
  public:
    virtual ~GDBResponse() = default;
    virtual std::string to_string() const = 0;
  };

}

#endif //XENDBG_GDBRESPONSEBASE_HPP
