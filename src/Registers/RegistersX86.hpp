//
// Created by Spencer Michaels on 9/25/18.
//

#ifndef XENDBG_REGISTERSX86_HPP
#define XENDBG_REGISTERSX86_HPP

#include "Register.hpp"

namespace xd::reg::x86 {

  DECLARE_REGISTER(cr3,    uint64_t, -1);

}

#endif //XENDBG_REGISTERSX86_HPP
