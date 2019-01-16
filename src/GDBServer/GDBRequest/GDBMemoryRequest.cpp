//
// Copyright (C) 2018-2019 NCC Group
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
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
