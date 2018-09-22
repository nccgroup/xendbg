//
// Created by Spencer Michaels on 9/20/18.
//

#ifndef XENDBG_GDBPACKETINTERPRETER_HPP
#define XENDBG_GDBPACKETINTERPRETER_HPP

#include "GDBConnection.hpp"
#include "GDBRequestPacket.hpp"
#include "GDBResponsePacket.hpp"

namespace xd::dbg {

  class DebugSession;

}

namespace xd::gdbsrv {

  void interpret_packet(
      xd::dbg::DebugSession &debugger,
      xd::gdbsrv::GDBConnection &client,
      const xd::gdbsrv::pkt::GDBRequestPacket &packet);
}

#endif //XENDBG_GDBPACKETINTERPRETER_HPP
