//
// Created by Spencer Michaels on 8/13/18.
//

#ifndef XENDBG_XENEXCEPTION_HPP
#define XENDBG_XENEXCEPTION_HPP

#include <stdexcept>
#include <string>

namespace xd::xen {

  class XenException : std::runtime_error {
  public:
    explicit XenException(const std::string& what)
        : std::runtime_error(what.c_str()) {}

    explicit XenException(const char* what)
        : std::runtime_error(what) {}
  };

}

#endif //XENDBG_XENEXCEPTION_HPP
