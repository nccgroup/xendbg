//
// Created by Spencer Michaels on 10/1/18.
//

#ifndef XENDBG_GDBQUERYRESPONSE_HPP
#define XENDBG_GDBQUERYRESPONSE_HPP

#include <sstream>
#include <string>
#include <vector>

#include "GDBResponseBase.hpp"

namespace xd::gdb::rsp {

  class QuerySupportedResponse : public GDBResponse {
  public:
    explicit QuerySupportedResponse(std::vector<std::string> features)
      : _features(std::move(features)) {};

    std::string to_string() const override {
      if (_features.empty())
        return "";

      std::stringstream ss;
      ss << _features.front();
      std::for_each(_features.begin()+1, _features.end(),
        [&ss](const auto& feature) {
          ss << ";" << feature;
        }
      );
      return ss.str();
    }

  private:
    std::vector<std::string> _features;
  };

  // NOTE: thread ID 0 = any thread, ID -1 = all threads
  // so these have to be zero-indexed.
  class QueryCurrentThreadIDResponse : public GDBResponse {
  public:
    explicit QueryCurrentThreadIDResponse(size_t thread_id)
      : _thread_id(thread_id) {}

    std::string to_string() const override {
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

  private:
    size_t _thread_id;
  };

  class QueryThreadInfoResponse : public GDBResponse {
  public:
    explicit QueryThreadInfoResponse(std::vector<size_t> thread_ids)
      : _thread_ids(std::move(thread_ids))
    {
      if (thread_ids.empty())
        throw std::runtime_error("Must provide at least one thread ID!");
    };

    std::string to_string() const override {
      std::stringstream ss;

      ss << "m";
      ss << std::hex;
      ss << _thread_ids.front();
      std::for_each(_thread_ids.begin()+1, _thread_ids.end(),
        [&ss](const auto& tid) {
          ss << "," << tid;
        });

      return ss.str();
    };

  private:
    const std::vector<size_t> _thread_ids;
  };

  class QueryThreadInfoEndResponse : public GDBResponse {
  public:
    std::string to_string() const override {
      return "l";
    };
  };

    // See https://github.com/llvm-mirror/lldb/blob/master/docs/lldb-gdb-remote.txt#L756
  class QueryHostInfoResponse : public GDBResponse {
  public:
    QueryHostInfoResponse(unsigned word_size, std::string hostname)
      : _word_size(word_size), _hostname(std::move(hostname))
    {};

    std::string to_string() const override {
      std::stringstream ss;


      ss << "triple:7838365f36342d70632d6c696e75782d676e75;ptrsize:8;endian:little;hostname:7468696e6b706164;";
      //add_list_entry(ss, "triple", hexify(make_triple()));
      add_list_entry(ss, "endian", "little"); // TODO can this ever be big?
      add_list_entry(ss, "ptrsize", _word_size);
      add_list_entry(ss, "hostname", hexify(_hostname));
      return ss.str();
    };

  private:
    std::string make_triple() const {
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

    unsigned _word_size;
    std::string _hostname;
  };

  class QueryProcessInfoResponse : public GDBResponse {
  public:
    QueryProcessInfoResponse(size_t pid)
      : _pid(pid) {};

    std::string to_string() const override {
      std::stringstream ss;
      add_list_entry(ss, "pid", _pid);
      add_list_entry(ss, "ptrsize", sizeof(uint64_t));
      add_list_entry(ss, "endian", "little");     // TODO
      return ss.str();
    };

  private:
    size_t _pid;
  };

  class QueryMemoryRegionInfoResponse : public GDBResponse {
  public:
    QueryMemoryRegionInfoResponse(xd::xen::Address start_address, size_t size,
        bool read, bool write, bool execute, std::string name = "")
      : _start_address(start_address), _size(size),
        _read(read), _write(write), _execute(execute),
        _name(std::move(name))
    {};

    std::string to_string() const override {
      std::stringstream ss;
      ss << std::hex;
      add_list_entry(ss, "start", _start_address);
      add_list_entry(ss, "size", _size);
      add_list_entry(ss, "permissions", make_permissions_string());
      if (!_name.empty())
        add_list_entry(ss, "name", _start_address);
      return ss.str();
    };

  private:
    std::string make_permissions_string() const {
      std::string s;
      if (_read)
        s += "r";
      if (_write)
        s += "w";
      if (_execute)
        s += "x";
      return s;
    }

    xd::xen::Address _start_address;
    size_t _size;
    bool _read, _write, _execute;
    std::string _name;
  };

  class QueryMemoryRegionInfoErrorResponse : public GDBResponse {
  public:
    QueryMemoryRegionInfoErrorResponse(std::string error)
      : _error(std::string(error))
    {};

    std::string to_string() const override {
      return "error:" + _error;
    };

  private:
    std::string _error;
  };

  class QueryRegisterInfoResponse : public GDBResponse {
  public:
    QueryRegisterInfoResponse(
        std::string name, size_t width, size_t offset,
          size_t gcc_register_id)
      : _name(std::move(name)), _width(width), _offset(offset),
        _gcc_register_id(gcc_register_id)
    {};

    std::string to_string() const override {
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

  private:
    std::string _name;
    size_t _width;
    size_t _offset;
    size_t _gcc_register_id;
  };

}

#endif //XENDBG_GDBQUERYRESPONSE_HPP
