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
#include "../Util/overloaded.hpp"

namespace xd::dbg {

  class NoGuestAttachedException : public std::exception {
  };

  class NoSuchInfiniteLoopException : public std::exception{
  public:
    explicit NoSuchInfiniteLoopException(const xen::Address address)
      : _address(address) {};

    xen::Address get_address() const { return _address; };

  private:
    xen::Address _address;
  };

  class NoSuchSymbolException : public std::runtime_error {
  public:
    explicit NoSuchSymbolException(const std::string &name)
      : std::runtime_error(name) {};
  };

  class Debugger {
  private:
    struct Symbol {
      uint64_t address;
    };

    using InfiniteLoopMap = std::unordered_map<xen::Address, uint16_t>;
    using MaskedMemory = std::unique_ptr<unsigned char>;

  public:
    xen::Domain& attach(xen::DomID domid);
    void detach();

    xen::Address continue_until_infinite_loop();
    void single_step();

    std::optional<xen::Domain>& get_current_domain() { return _domain; };

    const InfiniteLoopMap& get_infinite_loops() { return _infinite_loops; };

    void insert_infinite_loop(xen::Address address);
    void remove_infinite_loop(xen::Address address);

    MaskedMemory read_memory_masking_infinite_loops(
        xen::Address address, size_t length);
    void write_memory_retaining_infinite_loops(
        xen::Address address, size_t length, void *data);

  private:
    std::optional<xen::Address> check_infinite_loop_hit();
    std::pair<std::optional<xen::Address>,
              std::optional<xen::Address>> get_address_of_next_instruction();

    template <typename Reg32_t, typename Reg64_t>
    uint64_t read_register() {
      return std::visit(util::overloaded {
          [](const reg::x86_32::RegistersX86_32 regs) {
            return (uint64_t)regs.get<Reg32_t>();
          },
          [](const reg::x86_64::RegistersX86_64 regs) {
            return (uint64_t)regs.get<Reg64_t>();
          }
      }, _domain->get_cpu_context(_current_vcpu));
    }

  private:
    csh _capstone;
    xen::VCPU_ID _current_vcpu;
    xen::XenHandle _xen;
    std::optional<xen::Domain> _domain;

    InfiniteLoopMap _infinite_loops;
  };

}


#endif //XENDBG_DEBUGGER_HPP
