//
// Created by Spencer Michaels on 10/1/18.
//

#ifndef XENDBG_GDBMEMORYRESPONSE_HPP
#define XENDBG_GDBMEMORYRESPONSE_HPP

#include <sstream>
#include <vector>

#include "GDBResponseBase.hpp"

namespace xd::gdb::rsp {

  class MemoryReadResponse : public GDBResponse {
  public:
    explicit MemoryReadResponse(const unsigned char * const data, size_t length)
      : _data(data, data + length) {};

    std::string to_string() const override {
      std::stringstream ss;

      ss << std::hex << std::setfill('0');
      std::for_each(_data.begin(), _data.end(),
        [&ss](const unsigned char &ch) {
          ss << std::setw(2) << (unsigned)ch;
        });

      return ss.str();
    };

  private:
    std::vector<unsigned char> _data;
  };

}

#endif //XENDBG_GDBMEMORYRESPONSE_HPP
