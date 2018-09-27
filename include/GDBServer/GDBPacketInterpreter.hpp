//
// Created by Spencer Michaels on 9/20/18.
//

#ifndef XENDBG_GDBPACKETINTERPRETER_HPP
#define XENDBG_GDBPACKETINTERPRETER_HPP

#include <Xen/Domain.hpp>
#include "GDBConnection.hpp"
#include "GDBServer.hpp"
#include "GDBRequestPacket.hpp"
#include "GDBResponsePacket.hpp"

namespace xd::uv {

  class UVLoop;

}

namespace xd::dbg {

  class DebugSession;

}

namespace xd::gdbsrv {

  void interpret_packet(
      xd::xen::Domain &domain,
      xd::dbg::DebugSession &debugger,
      xd::gdbsrv::GDBServer &server,
      xd::gdbsrv::GDBConnection &connection,
      const xd::gdbsrv::pkt::GDBRequestPacket &packet);
}

#endif //XENDBG_GDBPACKETINTERPRETER_HPP
