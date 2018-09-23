//
// Created by Spencer Michaels on 9/19/18.
//

#ifndef XENDBG_SERVERMODECONTROLLER_HPP
#define XENDBG_SERVERMODECONTROLLER_HPP

#include <cstdint>
#include <unordered_map>

#include "UV/UVLoop.hpp"
#include "Xen/Domain.hpp"
#include "Xen/XenHandle.hpp"

namespace xd {

  class ServerModeController {
  public:
    ServerModeController(uint16_t base_port);

    void run();

  private:
    class Instance;

    xen::XenHandle _xen;
    uv::UVLoop _loop;
    uint16_t _next_port;
    std::unordered_map<xen::DomID, Instance> _instances;

    void add_instances();
    void prune_instances();

    class Instance {
    public:
      Instance(xen::Domain domain, uint16_t port) : _domain(std::move(domain)) {};

      const xen::Domain &get_domain() const { return _domain; };

    private:
      xen::Domain _domain;
    };
  };

}

#endif //XENDBG_SERVERMODECONTROLLER_HPP
