//
// Created by Spencer Michaels on 9/20/18.
//

#ifndef XENDBG_GDBPACKETINTERPRETER_HPP
#define XENDBG_GDBPACKETINTERPRETER_HPP

#include "GDBRequestPacket.hpp"
#include "GDBResponsePacket.hpp"
#include "../Debugger/DebugSessionPV.hpp"

namespace xd::gdbsrv {

  void interpret_packet(xd::dbg::DebugSessionPV &dbg, const pkt::GDBRequestPacket &pkt,
      std::function<void(const pkt::GDBResponsePacket&)>);

}

#endif //XENDBG_GDBPACKETINTERPRETER_HPP
