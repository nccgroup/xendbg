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
    explicit MemoryReadResponse(unsigned char * data, size_t length)
      : _data(data, data + length) {};

    std::string to_string() const override;

  private:
    std::vector<unsigned char> _data;
  };

}

#endif //XENDBG_GDBMEMORYRESPONSE_HPP