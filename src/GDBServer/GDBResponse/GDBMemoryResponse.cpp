//
// Created by Spencer Michaels on 10/1/18.
//

#include <GDBServer/GDBResponse/GDBMemoryResponse.hpp>

using namespace xd::gdb::rsp;

std::string MemoryReadResponse::to_string() const {
  std::stringstream ss;

  ss << std::hex << std::setfill('0');
  std::for_each(_data.begin(), _data.end(),
  [&ss](const unsigned char &ch) {
  ss << std::setw(2) << (unsigned)ch;
  });

  return ss.str();
};
