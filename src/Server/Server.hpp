//
// Created by Spencer Michaels on 9/19/18.
//

#ifndef XENDBG_SERVER_HPP
#define XENDBG_SERVER_HPP

#include <cstdint>
#include <unordered_map>

#include <uvw.hpp>

#include <Debugger/DebugSessionPV.hpp>
#include <Xen/DomainAny.hpp>

#include "ServerInstance.hpp"

namespace xd {

  class Server {
  public:
    explicit Server(uint16_t base_port);

    void run_single(xen::DomainAny domain);
    void run_multi();

  private:
    xen::XenEventChannel _xenevtchn;
    xen::XenCtrl _xenctrl;
    xen::XenForeignMemory _xenforeignmemory;
    xen::XenStore _xenstore;

    std::shared_ptr<uvw::Loop> _loop;
    std::shared_ptr<uvw::SignalHandle> _signal;
    std::shared_ptr<uvw::PollHandle> _poll;

    uint16_t _next_port;
    std::unordered_map<xen::DomID, std::unique_ptr<ServerInstance>> _instances;

  private:
    void run();

    void add_new_instances();
    void prune_instances();

    void add_instance(xen::DomainAny domain_any);
  };

}

#endif //XENDBG_SERVER_HPP