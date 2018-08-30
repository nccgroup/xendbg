//
// Created by Spencer Michaels on 8/12/18.
//

#ifndef XENDBG_UTIL_POP_RET_HPP
#define XENDBG_UTIL_POP_RET_HPP

#include <utility>

namespace xd::util {

  template <class Q>
  typename Q::value_type pop_ret(Q& q) {
    auto ret = std::move(q.top());
    q.pop();
    return ret;
  }

}

#endif //XENDBG_POP_HPP
