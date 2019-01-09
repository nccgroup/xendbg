//
// Copyright (C) 2018-2019 Spencer Michaels
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

//
// Created by Spencer Michaels on 10/1/18.
//

#include <GDBServer/GDBRequest/GDBRegisterRequest.hpp>

using namespace xd::gdb::req;

GeneralRegistersBatchReadRequest::GeneralRegistersBatchReadRequest(const std::string &data)
  : GDBRequestBase(data, 'g')
{
  if (check_char(';')) {
    expect_string("thread:");
    _thread_id = read_hex_number<size_t>();
    expect_char(';');
  } else {
    _thread_id = (size_t)-1;
  }
  expect_end();
};

RegisterReadRequest::RegisterReadRequest(const std::string &data)
  : GDBRequestBase(data, 'p')
{
  _register_id = read_hex_number<uint16_t>();
  if (check_char(';')) {
    expect_string("thread:");
    _thread_id = read_hex_number<size_t>();
    expect_char(';');
  } else {
    _thread_id = (size_t)-1;
  }
  expect_end();
};

RegisterWriteRequest::RegisterWriteRequest(const std::string &data)
  : GDBRequestBase(data, 'P')
{
  _register_id = read_hex_number<uint16_t>();
  expect_char('=');
  _value = read_hex_number_respecting_endianness<uint64_t>();
  if (check_char(';')) {
    expect_string("thread:");
    _thread_id = read_hex_number<size_t>();
    expect_char(';');
  }
  expect_end();
};

GeneralRegistersBatchWriteRequest::GeneralRegistersBatchWriteRequest(const std::string &data)
  : GDBRequestBase(data, 'g')
{
  using Regs64 = xd::reg::x86_64::RegistersX86_64;
  using Regs32 = xd::reg::x86_32::RegistersX86_32;

  size_t index = 0;
  const auto size = get_num_remaining()/2;

  if (size == Regs64::size) {
    Regs64::for_each_metadata([this, &index](const auto md) {
      const auto word = read_word(md);
      if (word)
        _values.push_back(std::make_pair(index, *word));
      ++index;
    });
  } else if (size == Regs32::size) {
    Regs32::for_each_metadata([this, &index](const auto md) {
      const auto word = read_word(md);
      if (word)
        _values.push_back(std::make_pair(index, *word));
      ++index;
    });
  } else {
    throw RequestPacketParseException("Invalid register packet size");
  }
  expect_end();
};
