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
