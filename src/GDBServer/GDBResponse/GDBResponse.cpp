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

#include <GDBServer/GDBResponse/GDBResponse.hpp>

using namespace xd::gdb::rsp;

std::string ErrorResponse::to_string() const {
  std::stringstream ss;
  ss << "E";
  ss << std::hex << std::setfill('0') << std::setw(2) << (unsigned)_error_code;
  if (!_message.empty())
    ss << ";" << _message;
  return ss.str();
}

std::string StopReasonSignalResponse::to_string() const {
  std::stringstream ss;
  ss << "T";
  ss << std::hex << std::setfill('0') << std::setw(2);
  ss << (unsigned)_signal;

  if (!_stop_reason_key.empty())
    ss << _stop_reason_key << ":" << _stop_reason_value << ";";

  ss << "thread:";
  ss << _thread_id;
  ss << ";threads:";
  if (_thread_ids.size() == 1)
    ss << _thread_ids.front();
  else
    for (const auto thread_id : _thread_ids)
      add_list_entry(ss, thread_id);
  ss << ";reason:signal;";
  return ss.str();
};
