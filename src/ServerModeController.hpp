//
// Created by Spencer Michaels on 9/19/18.
//

#ifndef XENDBG_SERVER_HPP
#define XENDBG_SERVER_HPP

#include <cstdint>
#include <unordered_map>

#include <uvw.hpp>

#include <Debugger/DebuggerPV.hpp>
#include <Xen/DomainAny.hpp>

#include "DebugSession.hpp"

namespace xd {

  class ServerModeController {
  public:
    explicit ServerModeController(uint16_t base_port);

    void run_single(xen::DomID domid);
    void run_multi();

  private:
    xen::XenEventChannel _xenevtchn;
    xen::XenCtrl _xenctrl;
    xen::XenForeignMemory _xenforeignmemory;
    xen::XenStore _xenstore;

    std::shared_ptr<uvw::Loop> _loop;
    std::shared_ptr<uvw::TcpHandle> _tcp;
    std::shared_ptr<uvw::SignalHandle> _signal;
    std::shared_ptr<uvw::PollHandle> _poll;

    uint16_t _next_port;
    std::unordered_map<xen::DomID, std::unique_ptr<DebugSessionBase>> _instances;

  private:
    void run();

    void add_new_instances();
    void prune_instances();

    void add_instance(xen::DomainAny domain_any);
  };

}

#endif //XENDBG_SERVER_HPP
