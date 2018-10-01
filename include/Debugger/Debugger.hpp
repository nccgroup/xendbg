//
// Created by Spencer Michaels on 9/20/18.
//

#ifndef XENDBG_DEBUGGER_HPP
#define XENDBG_DEBUGGER_HPP

#include <memory>
#include <stdexcept>
#include <vector>

#include <capstone/capstone.h>
#include <uvw.hpp>

#include <Util/overloaded.hpp>
#include <Xen/Common.hpp>
#include <Xen/Domain.hpp>

namespace xd::dbg {

  class CapstoneException : public std::runtime_error {
  public:
    CapstoneException(const std::string &msg)
      : std::runtime_error(msg) {};
  };

  class NoSuchBreakpointException : public std::exception {
  public:
    explicit NoSuchBreakpointException(const xen::Address address)
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

  class Debugger : public std::enable_shared_from_this<Debugger> {
  private:
    struct Symbol {
      xen::Address address;
    };

  public:
    using OnBreakpointHitFn = std::function<void(xen::Address)>;
    using MaskedMemory = std::unique_ptr<unsigned char>;

    Debugger(uvw::Loop &loop, xen::Domain &domain);
    virtual ~Debugger();

    size_t get_vcpu_id() { return _vcpu_id; }

    virtual void attach();
    virtual void detach();

    virtual void continue_() = 0;
    virtual xen::Address single_step() = 0;
    virtual std::optional<xen::Address> check_breakpoint_hit() = 0;
    void notify_breakpoint_hit(OnBreakpointHitFn on_breakpoint_hit); // TODO

    virtual void cleanup() = 0;
    virtual void insert_breakpoint(xen::Address address) = 0;
    virtual void remove_breakpoint(xen::Address address) = 0;

    virtual MaskedMemory read_memory_masking_breakpoints(xen::Address address, size_t length) = 0;
    virtual void write_memory_retaining_breakpoints(xen::Address address, size_t length, void *data) = 0;

  protected:
    std::pair<xen::Address,
              std::optional<xen::Address>> get_address_of_next_instruction();

  private:
    xen::Domain &_domain;
    std::shared_ptr<uvw::TimerHandle> _timer;
    csh _capstone;

    xen::VCPU_ID _vcpu_id;
  };

}


#endif //XENDBG_DEBUGGER_HPP
