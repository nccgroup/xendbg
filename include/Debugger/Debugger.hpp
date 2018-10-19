//
// Created by Spencer Michaels on 9/20/18.
//

#ifndef XENDBG_DEBUGGER_HPP
#define XENDBG_DEBUGGER_HPP

#include <memory>
#include <stdexcept>
#include <sys/mman.h>
#include <vector>

#include <capstone/capstone.h>
#include <spdlog/spdlog.h>
#include <uvw.hpp>

#include <Globals.hpp>
#include <Util/overloaded.hpp>
#include <Xen/Common.hpp>
#include <Xen/Domain.hpp>

#define X86_MAX_INSTRUCTION_SIZE 0x10

namespace xd::dbg {

  class CapstoneException : public std::runtime_error {
  public:
    explicit CapstoneException(const std::string &msg)
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

  class FeatureNotSupportedException : public std::runtime_error {
  public:
    explicit FeatureNotSupportedException(const std::string &msg)
      : std::runtime_error(msg)
    {};
  };

  using MaskedMemory = std::unique_ptr<unsigned char>;

  class Debugger : public std::enable_shared_from_this<Debugger> {
  public:
    using OnStopFn = std::function<void(int)>;

    explicit Debugger(uvw::Loop &loop, std::shared_ptr<xen::Domain> domain);
    virtual ~Debugger();

    virtual const xen::Domain &get_domain() { return *_domain; };

    virtual void attach();
    virtual void detach();

    void continue_();
    void single_step();

    void cleanup();

    void insert_breakpoint(xen::Address address);
    void remove_breakpoint(xen::Address address);

    virtual void insert_watchpoint(xen::Address address, uint32_t bytes, xenmem_access_t access);
    virtual void remove_watchpoint(xen::Address address, uint32_t bytes, xenmem_access_t access);

    void on_stop(OnStopFn on_stop);
    int get_last_stop_signal() { return _last_stop_signal; };

    MaskedMemory read_memory_masking_breakpoints(
        xen::Address address, size_t length);
    void write_memory_retaining_breakpoints(
        xen::Address address, size_t length, void *data);

    xen::VCPU_ID get_vcpu_id() { return _vcpu_id; };
    void set_vcpu_id(xen::VCPU_ID vcpu_id) { _vcpu_id = vcpu_id; };

  protected:
    void on_stop_internal(int signal);

  private:
    using BreakpointMap = std::unordered_map<xen::Address, uint8_t>;

    std::shared_ptr<xen::Domain> _domain;
    BreakpointMap _breakpoints;
    csh _capstone;
    std::shared_ptr<uvw::TimerHandle> _timer;
    OnStopFn _on_stop;

    xen::VCPU_ID _vcpu_id;
    bool _is_attached;
    int _last_stop_signal;
    xen::VCPU_ID _last_single_step_vcpu_id;
    std::optional<xen::Address> _last_single_step_breakpoint_addr;
    bool _is_single_stepping;
  };

}


#endif //XENDBG_DEBUGGER_HPP
