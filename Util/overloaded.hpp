//
// Created by Spencer Michaels on 8/12/18.
//

#ifndef XENDBG_UTIL_OVERLOADED_HPP
#define XENDBG_UTIL_OVERLOADED_HPP

namespace xd::util {

  template<class... Ts>
  struct overloaded : Ts ... { using Ts::operator()...; };
  template<class... Ts> overloaded(Ts...) -> overloaded<Ts...>;

}

#endif //XENDBG_OVERLOADED_HPP
