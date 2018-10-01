//
// Created by Spencer Michaels on 10/1/18.
//

#ifndef XENDBG_GDBMEMORYREQUEST_HPP
#define XENDBG_GDBMEMORYREQUEST_HPP

#include <vector>

#include "GDBRequestBase.hpp"

namespace xd::gdb::req {

  class MemoryReadRequest : public GDBRequestBase {
  public:
    explicit MemoryReadRequest(const std::string &data);

    uint64_t get_address() const { return _address; };
    uint64_t get_length() const { return _length; };

  private:
    uint64_t _address;
    uint64_t _length;
  };

  class MemoryWriteRequest : public GDBRequestBase {
  public:
    explicit MemoryWriteRequest(const std::string &data);

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
