//
// Created by Spencer Michaels on 8/28/18.
//

#ifndef XENDBG_DEBUGGER_HPP
#define XENDBG_DEBUGGER_HPP

#include <optional>
#include <memory>
#include <stdexcept>
#include <unordered_map>
#include <vector>

#include <capstone/capstone.h>

#include "../Xen/Domain.hpp"

namespace xd::dbg {

  class NoGuestAttachedException : public std::exception {
  };

  /*
  class NoSuchBreakpointException : public std::exception{
  public:
    NoSuchBreakpointException(const size_t id)
      : _id(id) {};

    size_t get_id() const { return _id; };

  private:
    size_t _id;
  };
  */

  class NoSuchInfiniteLoopException : public std::exception{
  public:
    NoSuchInfiniteLoopException(const xen::Address address)
      : _address(address) {};

    xen::Address get_address() const { return _address; };

  private:
    xen::Address _address;
  };

  class NoSuchVariableException : public std::runtime_error {
  public:
    NoSuchVariableException(const std::string &name)
      : std::runtime_error(name) {};
  };

  class NoSuchSymbolException : public std::runtime_error {
  public:
    NoSuchSymbolException(const std::string &name)
      : std::runtime_error(name) {};
  };

  class Debugger {
  private:
    struct Symbol {
      uint64_t address;
    };

    using InfiniteLoopMap = std::unordered_map<xen::Address, uint16_t>;
    using SymbolMap = std::unordered_map<std::string, Symbol>;
    using VarMap = std::unordered_map<std::string, uint64_t>;

  public:
    xen::Domain& attach(xen::DomID domid);
    void detach();

    void load_symbols_from_file(const std::string &name);

    xen::Address continue_until_infinite_loop();
    void single_step();

    xen::XenHandle &get_xen_handle() { return _xen; };
    std::optional<xen::Domain>& get_current_domain() { return _domain; };
    std::vector<xen::Domain> get_guest_domains();
    const Symbol &lookup_symbol(const std::string &name);

    const SymbolMap& get_symbols() { return _symbols; };
    const VarMap& get_vars() { return _variables; };

    uint64_t get_var(const std::string &name);
    void set_var(const std::string &name, uint64_t value);
    void delete_var(const std::string &name);

    void insert_infinite_loop(xen::Address address);
    void remove_infinite_loop(xen::Address address);
  private:
    std::optional<xen::Address> check_infinite_loop_hit();
    std::pair<std::optional<xen::Address>,
      std::optional<xen::Address>> get_address_of_next_instruction();

  private:
    csh _capstone;
    size_t _current_vcpu;
    xen::XenHandle _xen;
    std::optional<xen::Domain> _domain;

    SymbolMap _symbols;
    InfiniteLoopMap _infinite_loops;
    VarMap _variables;
  };

}


#endif //XENDBG_DEBUGGER_HPP
