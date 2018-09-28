//
// Created by Spencer Michaels on 9/19/18.
//

#ifndef XENDBG_SERVERINSTANCEPV_HPP
#define XENDBG_SERVERINSTANCEPV_HPP

#include <optional>

#include <Debugger/DebugSessionPV.hpp>
#include <GDBServer/GDBServer.hpp>
#include <UV/UVLoop.hpp>
#include <Xen/DomainPV.hpp>

#include "GDBPacketHandler.hpp"
#include "GDBServer/GDBServer.hpp"

namespace xd {

  class ServerInstancePV : public GDBServerInstance {
  public:
    ServerInstancePV(uv::UVLoop &loop, xen::DomainPV domain);

    xen::DomID get_domid() const override { return _domain.get_domid(); };

    void run(const std::string& address_str, uint16_t port) override;

  private:
    xen::DomainPV _domain;
    xd::dbg::DebugSessionPV _debugger;
    xd::gdbsrv::GDBServer _server;
    std::optional<GDBPacketHandler> _packet_handler;
  };

}

#endif //XENDBG_SERVERINSTANCEPV_HPP
