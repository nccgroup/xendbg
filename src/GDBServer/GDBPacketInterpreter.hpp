//
// Created by Spencer Michaels on 9/20/18.
//

#ifndef XENDBG_GDBPACKETINTERPRETER_HPP
#define XENDBG_GDBPACKETINTERPRETER_HPP

#include "GDBServer.hpp"
#include "GDBRequestPacket.hpp"
#include "GDBResponsePacket.hpp"

namespace xd::dbg {

  class DebugSession;

}

namespace xd::gdbsrv {

  void interpret_packet(
      const xd::gdbsrv::GDBServer::ClientHandle &client,
      const xd::gdbsrv::pkt::GDBRequestPacket &packet,
      xd::dbg::DebugSession &debugger);

}

#endif //XENDBG_GDBPACKETINTERPRETER_HPP
