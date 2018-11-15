//
// Created by Spencer Michaels on 10/1/18.
//

#ifndef XENDBG_GDBQUERYRESPONSE_HPP
#define XENDBG_GDBQUERYRESPONSE_HPP

#include <sstream>
#include <string>
#include <vector>
#include <Xen/Common.hpp>

#include "GDBResponseBase.hpp"

namespace xd::gdb::rsp {

  class QueryWatchpointSupportInfoResponse : public GDBResponse {
  public:
    explicit QueryWatchpointSupportInfoResponse(size_t num)
      : _num(num) {};

    std::string to_string() const override;

  private:
    size_t _num;
  };

  class QuerySupportedResponse : public GDBResponse {
  public:
    explicit QuerySupportedResponse(std::vector<std::string> features)
      : _features(std::move(features)) {};

    std::string to_string() const override;

  private:
    std::vector<std::string> _features;
  };

  // NOTE: thread ID 0 = any thread, ID -1 = all threads
  // so these have to be zero-indexed.
  class QueryCurrentThreadIDResponse : public GDBResponse {
  public:
    explicit QueryCurrentThreadIDResponse(size_t thread_id)
      : _thread_id(thread_id) {}

    std::string to_string() const override;

  private:
    size_t _thread_id;
  };

  class QueryThreadInfoResponse : public GDBResponse {
  public:
    explicit QueryThreadInfoResponse(std::vector<size_t> thread_ids);

    std::string to_string() const override;

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

    std::string to_string() const override;

  private:
    std::string make_triple() const;

    unsigned _word_size;
    std::string _hostname;
  };

  class QueryProcessInfoResponse : public GDBResponse {
  public:
    explicit QueryProcessInfoResponse(size_t pid)
      : _pid(pid) {};

    std::string to_string() const;

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

    std::string to_string() const override;

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
    explicit QueryMemoryRegionInfoErrorResponse(std::string error)
      : _error(std::move(error))
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

    std::string to_string() const override;

  private:
    std::string _name;
    size_t _width;
    size_t _offset;
    size_t _gcc_register_id;
  };

}

#endif //XENDBG_GDBQUERYRESPONSE_HPP
