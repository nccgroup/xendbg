//
// Created by Spencer Michaels on 8/13/18.
//

#ifndef XENDBG_XENEXCEPTION_HPP
#define XENDBG_XENEXCEPTION_HPP

#include <stdexcept>
#include <string>

namespace xd::xen {

  class XenException : public std::runtime_error {
  public:
    explicit XenException(const std::string& what)
        : std::runtime_error(what.c_str()), _err(0) {};

    explicit XenException(const char* what)
        : std::runtime_error(what), _err(0) {};

    explicit XenException(const std::string& what, int err)
        : std::runtime_error(what.c_str()), _err(err) {};

    explicit XenException(const char* what, int err)
        : std::runtime_error(what), _err(err) {};

    int get_err() const { return _err; };

  private:
    int _err;
  };

}

#endif //XENDBG_XENEXCEPTION_HPP
