//
// Created by Spencer Michaels on 10/1/18.
//

#include <GDBServer/GDBRequest/GDBMemoryRequest.hpp>

using namespace xd::gdb::req;

MemoryReadRequest::MemoryReadRequest(const std::string &data)
  : GDBRequestBase(data, 'm')
{
  _address = read_hex_number<uint64_t>();
  expect_char(',');
  _length = read_hex_number<uint64_t>();
  expect_end();
};

MemoryWriteRequest::MemoryWriteRequest(const std::string &data)
  : GDBRequestBase(data, 'M')
{
  _address = read_hex_number<uint64_t>();
  expect_char(',');
  _length = read_hex_number<uint64_t>();
  expect_char(':');

  _data.reserve(_length);
  for (size_t i = 0; i < _length; ++i)
    _data.push_back(read_byte());

  expect_end();
};
