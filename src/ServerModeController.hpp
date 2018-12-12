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
    explicit ServerModeController(std::string address, uint16_t base_port, bool non_stop_mode);

    void run_single(const std::string &name);
    void run_single(xen::DomID domid);
    void run_multi();

  private:
    std::shared_ptr<xen::Xen> _xen;

    std::shared_ptr<uvw::Loop> _loop;
    std::shared_ptr<uvw::TcpHandle> _tcp;
    std::shared_ptr<uvw::SignalHandle> _signal;
    std::shared_ptr<uvw::PollHandle> _poll;

    std::string _address;
    uint16_t _next_port;
    bool _non_stop_mode;
    std::unordered_map<xen::DomID, std::unique_ptr<DebugSession>> _instances;

  private:
    static xen::DomID get_domid_any(const xen::DomainAny &domain_any);
    static std::string get_name_any(const xen::DomainAny &domain_any);

    void run();
    void stop();

    size_t add_new_instances();
    size_t prune_instances();

    template <typename F>
    size_t for_terminated_instances(F f) {
      const auto domains = _xen->get_domains();

      size_t num_removed = 0;
      auto it = _instances.begin();
      while (it != _instances.end()) {
        if (std::none_of(domains.begin(), domains.end(),
          [&](const auto &domain) {
            return get_domid_any(domain) == it->first;
          }))
        {
          f(it);
          ++num_removed;
        } else {
          ++it;
        }
      }
      return num_removed;
    }

    void add_instance(xen::DomainAny domain);
  };

}

#endif //XENDBG_SERVER_HPP
