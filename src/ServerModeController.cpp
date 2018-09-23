#include <iostream>

#include "ServerModeController.hpp"
#include "UV/UVPoll.hpp"
#include "UV/UVSignal.hpp"

using xd::ServerModeController;
using xd::uv::UVPoll;
using xd::uv::UVSignal;

ServerModeController::ServerModeController(uint16_t base_port)
  : _next_port(base_port)
{
}

void ServerModeController::run() {
  UVSignal signal(_loop);
  signal.start([this]() {
    _loop.stop();
  }, SIGINT);

  auto &xenstore = _xen.get_xenstore();

  auto watch_introduce = xenstore.add_watch();
  watch_introduce.add_path("@introduceDomain");

  auto watch_release = xenstore.add_watch();
  watch_release.add_path("@releaseDomain");

  uv::UVPoll poll(_loop, xenstore.get_fileno());
  poll.start([&](const auto &event) {
    if (event.readable) {
      if (watch_introduce.check())
        add_instances();
      else if (watch_release.check())
        prune_instances();
    }
  });

  _loop.start();
}

void ServerModeController::add_instances() {
  const auto domains = _xen.get_domains();


  std::for_each(domains.begin(), domains.end(),
    [&](const auto &domain) {
      const auto domid = domain.get_domid();
      if (_instances.count(domid)) {
        std::cout << "[+] Port " << _next_port << ": domain " << domid << std::endl;
        _instances.emplace(domid, Instance(domain, _next_port++));
      }
    });
}

void ServerModeController::prune_instances() {
  const auto domains = _xen.get_domains();

  _instances.erase(std::remove_if(
        _instances.begin(), _instances.end(),
        [&](auto &kv) {
          return std::none_of(domains.begin(), domains.end(),
            [&](const auto &domain) {
              return kv.second.get_domain() == domain;
            });
        }),
    _instances.end());
}
