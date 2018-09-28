//
// Created by Spencer Michaels on 9/19/18.
//

#ifndef XENDBG_SERVERINSTANCEPV_HPP
#define XENDBG_SERVERINSTANCEPV_HPP

#include <optional>

#include <uvw.hpp>

#include <Debugger/DebugSessionPV.hpp>
#include <GDBServer/GDBServer.hpp>
#include <Xen/DomainPV.hpp>

#include "GDBPacketHandler.hpp"
#include "GDBServer/GDBServer.hpp"

namespace xd::gdbsrv {

  class GDBServerPV : public GDBServer {
  public:
    GDBServerPV(uvw::Loop &loop, xen::DomainPV domain);

    void run(const std::string& address_str, uint16_t port) override;

  private:
    xen::DomainPV _domain;
    xd::dbg::DebugSessionPV _debugger;
    std::optional<GDBPacketHandler> _packet_handler;
  };

}

#endif //XENDBG_SERVERINSTANCEPV_HPP
