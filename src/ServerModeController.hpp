//
// Created by Spencer Michaels on 9/19/18.
//

#ifndef XENDBG_SERVER_HPP
#define XENDBG_SERVER_HPP

#include <cstdint>
#include <stdexcept>
#include <unordered_map>

#include <uvw.hpp>

#include <Xen/Xen.hpp>

#include "DebugSession.hpp"

namespace xd {

  class DomainAlreadyAddedException : public std::exception {
  public:
    explicit DomainAlreadyAddedException(xen::DomID domid)
      : _domid(domid) {};

    xen::DomID get_domid() { return _domid; };

  private:
    xen::DomID _domid;
  };

  class ServerModeController {
  public:
    explicit ServerModeController(uint16_t base_port);

    void run_single(const std::string &name);
    void run_single(xen::DomID domid);
    void run_multi();

  private:
    xen::Xen::SharedPtr _xen;

    std::shared_ptr<uvw::Loop> _loop;
    std::shared_ptr<uvw::TcpHandle> _tcp;
    std::shared_ptr<uvw::SignalHandle> _signal;
    std::shared_ptr<uvw::PollHandle> _poll;

    uint16_t _next_port;
    std::unordered_map<xen::DomID, std::unique_ptr<DebugSession>> _instances;

  private:
    void run();

    size_t add_new_instances();
    size_t prune_instances();

    void add_instance(std::shared_ptr<xen::Domain> domain);
  };

}

#endif //XENDBG_SERVER_HPP
