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
#include <Xen/Domain.hpp>
#include <Xen/XenHandle.hpp>

namespace xd {

  class ServerModeController {
  public:
    ServerModeController(uint16_t base_port);

    void run();

  private:
    class Instance;

    xen::XenHandlePtr _xen;
    uv::UVLoop _loop;
    uint16_t _next_port;
    std::unordered_map<xen::DomID, Instance> _instances;

    void add_instances();
    void prune_instances();

    class Instance {
    public:
      Instance(uv::UVLoop &loop, xen::Domain domain);

      Instance(Instance&& other) = default;
      Instance(const Instance& other) = delete;
      Instance& operator=(Instance&& other) = default;
      Instance& operator=(const Instance& other) = delete;

      xen::DomID get_domid() const { return _domid; };

      void run(const std::string& address_str, uint16_t port);

    private:
      xen::DomID _domid;
      xd::gdbsrv::GDBServer _server;
      std::unique_ptr<xd::dbg::DebugSession> _debugger;
    };
  };

}

#endif //XENDBG_SERVERMODECONTROLLER_HPP
