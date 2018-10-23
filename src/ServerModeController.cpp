#include <csignal>
#include <iostream>

#include <spdlog/spdlog.h>

#include <Globals.hpp>

#include "Debugger/Debugger.hpp"
#include "Debugger/DebuggerHVM.hpp"
#include "DebugSession.hpp"
#include "ServerModeController.hpp"

using xd::ServerModeController;
using xd::DebugSession;
using xd::xen::Xen;

xd::xen::DomID get_domid_any(const xd::xen::DomainAny &domain_any) {
  return std::visit(xd::util::overloaded {
    [](const auto &domain) {
      return domain.get_domid();
    }
  }, domain_any);
}

std::string get_name_any(const xd::xen::DomainAny &domain_any) {
  return std::visit(xd::util::overloaded {
      [](const auto &domain) {
        return domain.get_name();
      }
  }, domain_any);
}

ServerModeController::ServerModeController(uint16_t base_port)
  : _xen(Xen::create()),
    _loop(uvw::Loop::getDefault()),
    _signal(_loop->resource<uvw::SignalHandle>()),
    _poll(_loop->resource<uvw::PollHandle>(_xen->xenstore.get_fileno())),
    _next_port(base_port)
{
}

void ServerModeController::run_single(const std::string &name) {
  const auto domains = _xen->get_domains();

  auto found = std::find_if(domains.begin(), domains.end(), [&](const auto &domain) {
    return get_name_any(domain) == name;
  });

  if (found == domains.end())
    throw std::runtime_error("No such domain!");

  run_single(get_domid_any(*found));
}

void ServerModeController::run_single(xen::DomID domid) {
  auto &watch_release = _xen->xenstore.add_watch();
  watch_release.add_path("@releaseDomain");

  _poll->on<uvw::PollEvent>([&](const auto &event, auto &handle) {
    if (watch_release.check())
      if (prune_instances())
        handle.loop().stop();
  });

  _poll->start(uvw::PollHandle::Event::READABLE);

  auto domain_any = _xen->init_domain(domid);
  add_instance(domain_any);

  run();
}

void ServerModeController::run_multi() {
  auto &watch_introduce = _xen->xenstore.add_watch();
  watch_introduce.add_path("@introduceDomain");

  auto &watch_release = _xen->xenstore.add_watch();
  watch_release.add_path("@releaseDomain");

  _poll->on<uvw::PollEvent>([&](const auto&, auto&) {
    if (watch_introduce.check())
      add_new_instances();
    else if (watch_release.check())
      prune_instances();
  });

  _poll->start(uvw::PollHandle::Event::READABLE);

  run();
}

void ServerModeController::run() {
  _signal->once<uvw::SignalEvent>([this](const auto &event, auto &handle) {
    handle.loop().walk([](auto &handle) {
      handle.close();
    });
    handle.loop().run();
    //_instances.clear();
    exit(0);
  });
  
  _signal->start(SIGINT);

  _loop->run();
}

size_t ServerModeController::add_new_instances() {
  const auto domains = _xen->get_domains();

  size_t num_added = 0;
  for (const auto &domain : domains) {
    const auto domid = get_domid_any(domain);
    if (!_instances.count(domid)) {
      add_instance(domain);
      ++num_added;
    }
  }

  return num_added;
}

size_t ServerModeController::prune_instances() {
  const auto domains = _xen->get_domains();

  size_t num_removed = 0;
  auto it = _instances.begin();
  while (it != _instances.end()) {
    if (std::none_of(domains.begin(), domains.end(),
      [&](const auto &domain) {
        return get_domid_any(domain) == it->first;
      }))
    {
      spdlog::get(LOGNAME_CONSOLE)->info(
          "DOWN: Domain {0:d}", it->first);
      it = _instances.erase(it);
      ++num_removed;
    } else {
      ++it;
    }
  }

  return num_removed;
}

void ServerModeController::add_instance(xen::DomainAny domain_any) {
  const auto domid = get_domid_any(domain_any);

  if (_instances.count(domid))
    throw DomainAlreadyAddedException(domid);

  spdlog::get(LOGNAME_CONSOLE)->info(
      "UP: Domain {0:d} @ port {1:d}", domid, _next_port);

  std::shared_ptr<dbg::Debugger> debugger;
  std::visit(util::overloaded {
    [&](xen::DomainHVM domain) {
      debugger = std::static_pointer_cast<dbg::Debugger>(
          std::make_shared<dbg::DebuggerHVM>(
              *_loop, std::move(domain), _xen->xendevicemodel, _xen->xenevtchn));
    },
    [&](xen::DomainPV domain) {
      /*std::static_pointer_cast<dbg::Debugger>(
          std::make_shared<dbg::Debugger>(
              *_loop, std::move(domain)));*/
    },
  }, domain_any);

  auto [kv, _] = _instances.emplace(domid, std::make_unique<DebugSession>(*_loop, std::move(debugger)));
  kv->second->run("127.0.0.1", _next_port++);
}
