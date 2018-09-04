//
// Created by Spencer Michaels on 8/12/18.
//

#ifndef XENDBG_UTIL_CLEAR_HPP
#define XENDBG_UTIL_CLEAR_HPP

namespace xd::util {

  template<typename Container>
  void clear(Container &c) {
    //Container().swap(c);
    while (!c.empty())
      c.pop();
  }

}

#endif //XENDBG_UTIL_CLEAR_HPP
