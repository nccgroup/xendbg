
//
// Created by Spencer Michaels on 9/19/18.
//

#ifndef XENDBG_SERVERINSTANCE_HPP
#define XENDBG_SERVERINSTANCE_HPP

#include <string>

#include <Xen/Common.hpp>

namespace xd {

  class ServerInstance {
  public:
    virtual ~ServerInstance() = default;

    virtual xen::DomID get_domid() const = 0;
    virtual void run(const std::string& address_str, uint16_t port) = 0;
  };

}

#endif //XENDBG_SERVERINSTANCE_HPP
