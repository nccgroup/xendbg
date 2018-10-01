//
// Created by Spencer Michaels on 10/1/18.
//

#include <GDBServer/GDBResponse/GDBQueryResponse.hpp>

using namespace xd::gdb::rsp;

std::string QuerySupportedResponse::to_string() const {
  if (_features.empty())
    return "";

  std::stringstream ss;
  ss << _features.front();
  std::for_each(
      _features.begin()+1, _features.end(),
      [&ss](const auto& feature) {
        ss << ";" << feature;
      }
  );
  return ss.str();
}


std::string QueryCurrentThreadIDResponse::to_string() const {
  std::stringstream ss;
  ss << "QC";
  if (_thread_id == (size_t)-1) {
    ss << "-1";
  } else {
    ss << std::hex;
    ss << _thread_id;
  }
  return ss.str();
}

QueryThreadInfoResponse::QueryThreadInfoResponse(std::vector<size_t> thread_ids)
  : _thread_ids(std::move(thread_ids))
{
  if (thread_ids.empty())
    throw std::runtime_error("Must provide at least one thread ID!");
};

std::string QueryThreadInfoResponse::to_string() const {
  std::stringstream ss;

  ss << "m";
  ss << std::hex;
  ss << _thread_ids.front();
  std::for_each(
      _thread_ids.begin()+1, _thread_ids.end(),
      [&ss](const auto& tid) {
        ss << "," << tid;
      });

  return ss.str();
};

std::string QueryHostInfoResponse::to_string() const {
  std::stringstream ss;

  ss << "triple:7838365f36342d70632d6c696e75782d676e75;ptrsize:8;endian:little;hostname:7468696e6b706164;";
  //add_list_entry(ss, "triple", hexify(make_triple()));
  add_list_entry(ss, "endian", "little"); // TODO can this ever be big?
  add_list_entry(ss, "ptrsize", _word_size);
  add_list_entry(ss, "hostname", hexify(_hostname));
  return ss.str();
};

std::string QueryHostInfoResponse::make_triple() const {
  const auto arch = (_word_size == sizeof(uint64_t)) ? "x86_64" : "x86";
  const auto vendor = "pc";
  const auto os_type = "nacl";

  std::string triple;
  triple += arch;
  triple += "-";
  triple += vendor;
  triple += "-";
  triple += os_type;

  return triple;
}

std::string QueryProcessInfoResponse::to_string() const {
  std::stringstream ss;
  add_list_entry(ss, "pid", _pid);
  add_list_entry(ss, "ptrsize", sizeof(uint64_t));
  add_list_entry(ss, "endian", "little");     // TODO
  return ss.str();
};



std::string QueryMemoryRegionInfoResponse::to_string() const {
  std::stringstream ss;
  ss << std::hex;
  add_list_entry(ss, "start", _start_address);
  add_list_entry(ss, "size", _size);
  add_list_entry(ss, "permissions", make_permissions_string());
  if (!_name.empty())
    add_list_entry(ss, "name", _start_address);
  return ss.str();
};

std::string QueryRegisterInfoResponse::to_string() const {
  std::stringstream ss;
  add_list_entry(ss, "name", _name);
  add_list_entry(ss, "bitsize", _width);
  add_list_entry(ss, "offset", _offset);
  add_list_entry(ss, "encoding", "uint");
  add_list_entry(ss, "format", "hex");
  add_list_entry(ss, "set", "General Purpose Registers");
  if (_gcc_register_id != (size_t)-1) {
    add_list_entry(ss, "ehframe", _gcc_register_id);
    add_list_entry(ss, "dwarf", _gcc_register_id); // TODO
  }
  return ss.str();
};
