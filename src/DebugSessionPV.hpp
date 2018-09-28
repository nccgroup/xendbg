//
// Created by Spencer Michaels on 9/19/18.
//

#ifndef XENDBG_SERVERINSTANCEPV_HPP
#define XENDBG_SERVERINSTANCEPV_HPP

#include <optional>

#include <uvw.hpp>

#include <Debugger/DebuggerPV.hpp>
#include <GDBServer/GDBServer.hpp>
#include <Xen/DomainPV.hpp>

#include "DebugSession.hpp"
#include "GDBServer/GDBPacketHandler.hpp"
#include "GDBServer/GDBServer.hpp"

namespace xd {

  class DebugSessionPV : public DebugSession {
  public:
    DebugSessionPV(uvw::Loop &loop, xen::DomainPV domain);

    void run(const std::string& address_str, uint16_t port) override;

  private:
    xen::DomainPV _domain;
    std::shared_ptr<xd::dbg::DebuggerPV> _debugger;
    std::shared_ptr<xd::gdbsrv::GDBServer> _gdb_server;
    std::shared_ptr<xd::gdbsrv::GDBConnection> _gdb_connection;
    std::optional<gdbsrv::GDBPacketHandler> _packet_handler;
  };

}

#endif //XENDBG_SERVERINSTANCEPV_HPP
