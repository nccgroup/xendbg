//
// Created by smichaels on 9/28/18.
//

#ifndef XENDBG_DEBUGSESSION_HPP
#define XENDBG_DEBUGSESSION_HPP

#include <cstdint>
#include <string>

namespace xd {

  class DebugSession {
  public:
    virtual void run(const std::string& address_str, uint16_t port) = 0;
  };

}

#endif //XENDBG_DEBUGSESSION_HPP
