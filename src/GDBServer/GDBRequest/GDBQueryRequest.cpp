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

#include <GDBServer/GDBRequest/GDBQueryRequest.hpp>

using namespace xd::gdb::req;

QueryWatchpointSupportInfo::QueryWatchpointSupportInfo(const std::string &data)
  : GDBRequestBase(data, "qWatchpointSupportInfo")
{
  check_char(':');
  expect_end();
};

QuerySupportedRequest::QuerySupportedRequest(const std::string &data)
  : GDBRequestBase(data, "qSupported")
{
  expect_char(':');
  while (has_more()) {
    const auto feature = read_until_char_or_end(';');
    _features.push_back(feature);
  }
  expect_end();
};

QueryRegisterInfoRequest::QueryRegisterInfoRequest(const std::string &data)
  : GDBRequestBase(data, "qRegisterInfo")
{
  _register_id = read_hex_number<uint16_t>();
  expect_end();
};

QueryMemoryRegionInfoRequest::QueryMemoryRegionInfoRequest(const std::string &data)
  : GDBRequestBase(data, "qMemoryRegionInfo")
{
  expect_char(':');
  _address = read_hex_number<uint64_t>();
  expect_end();
};
