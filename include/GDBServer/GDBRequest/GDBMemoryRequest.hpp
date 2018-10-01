//
// Created by Spencer Michaels on 10/1/18.
//

#ifndef XENDBG_GDBMEMORYREQUEST_HPP
#define XENDBG_GDBMEMORYREQUEST_HPP

#include "GDBRequestBase.hpp"

namespace xd::gdb::req {

  class MemoryReadRequest : public GDBRequestBase {
  public:
    explicit MemoryReadRequest(const std::string &data)
        : GDBRequestBase(data, 'm') {
      _address = read_hex_number<uint64_t>();
      expect_char(',');
      _length = read_hex_number<uint64_t>();
      expect_end();
    };

    uint64_t get_address() const { return _address; };

    uint64_t get_length() const { return _length; };

  private:
    uint64_t _address;
    uint64_t _length;
  };

  class MemoryWriteRequest : public GDBRequestBase {
  public:
    explicit MemoryWriteRequest(const std::string &data)
        : GDBRequestBase(data, 'M') {
      _address = read_hex_number<uint64_t>();
      expect_char(',');
      _length = read_hex_number<uint64_t>();
      expect_char(':');

      _data.reserve(_length);
      for (size_t i = 0; i < _length; ++i)
        _data.push_back(read_byte());

      expect_end();
    };

    uint64_t get_address() const { return _address; };

    uint64_t get_length() const { return _length; };

    const std::vector<unsigned char> &get_data() const { return _data; };

  private:
    uint64_t _address;
    uint64_t _length;
    std::vector<unsigned char> _data;
  };

}

#endif //XENDBG_GDBMEMORYREQUEST_HPP
