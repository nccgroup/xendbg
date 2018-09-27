//
// Created by Spencer Michaels on 9/19/18.
//

#ifndef XENDBG_SERVERMODECONTROLLER_HPP
#define XENDBG_SERVERMODECONTROLLER_HPP

#include <cstdint>
#include <unordered_map>

#include <Debugger/DebugSessionPV.hpp>
#include <GDBServer/GDBServer.hpp>
#include <UV/UVLoop.hpp>
#include <Xen/DomainAny.hpp>

#include "ServerInstance.hpp"

namespace xd {

  class ServerModeController {
  public:
    ServerModeController(uint16_t base_port);

    void run();

  private:
    xen::XenEventChannel _xenevtchn;
    xen::XenCtrl _xenctrl;
    xen::XenForeignMemory _xenforeignmemory;
    xen::XenStore _xenstore;

    uv::UVLoop _loop;
    uint16_t _next_port;
    std::unordered_map<xen::DomID, std::unique_ptr<ServerInstance>> _instances;

  private:
    void add_instances();
    void prune_instances();
  };

}

#endif //XENDBG_SERVERMODECONTROLLER_HPP
