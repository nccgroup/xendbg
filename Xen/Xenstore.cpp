//
// Created by Spencer Michaels on 8/13/18.
//

#include <xenstore.h>

#include "XenException.hpp"
#include "Xenstore.hpp"

using xd::xen::DomID;
using xd::xen::XenException;
using xd::xen::Xenstore;

Xenstore::Xenstore()
    : _xenstore(xs_open(0), xs_close)
{
  if (!_xenstore)
    throw XenException("Failed to open Xenstore handle!");
}

std::vector<std::string> Xenstore::read_directory(const std::string &dir) {
  unsigned int num_entries;
  char **entries= xs_directory(_xenstore, XBT_NULL, dir, &num_entries);

  if (!entries)
    throw XenException("Read from directory \"" + dir + "\" failed!");

  std::vector<std::string> ret;
  ret.reserve(num_entries);

  for (int i = 0; i < num_entries; ++i) {
    const auto entry = entries[i];
    if (entry)
      ret.push_back(std::string(entry));
  }

  return ret;
}

std::string Xenstore::read(const std::string &file) {
  xs_transaction_t transaction;

  auto transaction_handle = xs_transaction_start(_xenstore, transaction);
  char *contents = (char*)xs_read(_xenstore, transaction, file.c_str(), nullptr);
  xs_transaction_end(_xenstore, transaction, false);

  if (!contents)
    throw XenException("Read from \"" + file + "\" failed!");

  return std::string(contents);
}

DomID Xenstore::get_domid_from_name(const std::string& name) {
  auto domain_ids = _xenstore.read_directory("/local/domain");

  for (auto domid : domain_ids) {
    auto path = "local/domain/" + domid + "/name";
    auto name_candidate = _xenstore.read(path);

    if (name_candidate == name) {
      return (uint32_t)std::stoul(domid, nullptr, 10);
    }
  }

  // If we got here, the domain wasn't found
  throw XenException("Domain \"" + name + "\" not found!");
}
