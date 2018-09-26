//
// Created by Spencer Michaels on 8/13/18.
//

#include <iostream>

#include <Util/pop_ret.hpp>
#include <Xen/XenException.hpp>
#include <Xen/XenStore.hpp>

using xd::util::pop_ret;
using xd::xen::DomID;
using xd::xen::XenException;
using xd::xen::XenStore;

XenStore::XenStore()
    : _xenstore(xs_open(0), &xs_close), _next_watch_id(0)
{
  if (!_xenstore)
    throw XenException("Failed to open Xenstore handle!");
}

int XenStore::get_fileno() const {
  return xs_fileno(_xenstore.get());
}

std::vector<std::string> XenStore::read_directory(const std::string &dir) const {
  unsigned int num_entries;
  char **entries = xs_directory(_xenstore.get(), XBT_NULL, dir.c_str(), &num_entries);

  if (!entries)
    throw XenException("Read from directory \"" + dir + "\" failed!", errno);

  std::vector<std::string> ret;
  ret.reserve(num_entries);

  for (size_t i = 0; i < num_entries; ++i) {
    const auto entry = entries[i];
    if (entry)
      ret.push_back(std::string(entry));
  }

  return ret;
}

std::string XenStore::read(const std::string &file) const {

  auto transaction = xs_transaction_start(_xenstore.get());
  char *contents = (char*)xs_read(_xenstore.get(), transaction, file.c_str(), nullptr);
  xs_transaction_end(_xenstore.get(), transaction, false);

  if (!contents)
    throw XenException("Read from \"" + file + "\" failed!", errno);

  return std::string(contents);
}

XenStore::Watch &XenStore::add_watch() {
  const auto token = std::to_string(_next_watch_id++);
  auto [it, _] = _watches.emplace(token, Watch(*this, token));
  return it->second;
}

void XenStore::check_watches() {
  while (true) {
    const auto event = xs_check_watch(_xenstore.get());
    if (!event)
      break;

    const auto path = event[0];
    const auto token = event[1];
    _watches.at(token)._events.push(std::move(path));
  }

  if (errno != EAGAIN)
    throw XenException("Failed to check watch!");
}

XenStore::Watch::Watch(XenStore &xenstore, std::string token)
  : _xenstore(xenstore), _token(token)
{
}

XenStore::Watch::~Watch() {
  for (const auto &path : _paths)
    xs_unwatch(_xenstore._xenstore.get(), path.c_str(), _token.c_str());
}

void XenStore::Watch::add_path(Path path) {
  xs_watch(_xenstore._xenstore.get(), path.c_str(), _token.c_str());
  _paths.push_back(std::move(path));
}

std::optional<XenStore::Path> XenStore::Watch::check() {
  if (_events.empty())
    _xenstore.check_watches();

  if (_events.empty())
    return std::nullopt;

  return pop_ret(_events);
}
