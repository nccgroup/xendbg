//
// Created by Spencer Michaels on 9/20/18.
//

#ifndef XENDBG_GDBPACKETINTERPRETER_HPP
#define XENDBG_GDBPACKETINTERPRETER_HPP

#include "GDBRequestPacket.hpp"
#include "GDBResponsePacket.hpp"

namespace xd::dbg {

  class DebugSessionPV;

}

namespace xd::gdbsrv {

  class GDBServer {
  public:
    class ClientID;
  };

  class GDBPacketInterpreterInterface {
  public:
    virtual void interpret(GDBServer::ClientID client,
        const pkt::GDBRequestPacket &packet) = 0;
  };

  class GDBPacketInterpreter : public GDBPacketInterpreterInterface {
  public:
    GDBPacketInterpreter(xd::gdbsrv::GDBServer &server, xd::dbg::DebugSessionPV &debugger);

    void interpret(GDBServer::ClientID client,
        const pkt::GDBRequestPacket &packet) override;

  private:
    xd::gdbsrv::GDBServer &_server;
    xd::dbg::DebugSessionPV &_debugger;
  };

}

#endif //XENDBG_GDBPACKETINTERPRETER_HPP
