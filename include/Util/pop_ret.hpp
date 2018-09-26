//
// Created by Spencer Michaels on 8/12/18.
//

#ifndef XENDBG_UTIL_POP_RET_HPP
#define XENDBG_UTIL_POP_RET_HPP

#include <stack>
#include <stdexcept>
#include <queue>
#include <utility>

namespace xd::util {

  template <typename C, typename V>
  struct _pop_ret_impl {
    static V pop_ret(C& c) {
      if (c.empty())
        throw std::runtime_error("Can't pop_ret an empty cueue!");
      auto ret = std::move(c.front());
      c.pop();
      return ret;
    }
  };

  template <typename V>
  struct _pop_ret_impl<std::stack<V>, V> {
    static V pop_ret(std::stack<V>& c) {
      if (c.empty())
        throw std::runtime_error("Can't pop_ret an empty cueue!");
      auto ret = std::move(c.top());
      c.pop();
      return ret;
    }
  };

  template <typename C>
  typename C::value_type pop_ret(C& c) {
    return _pop_ret_impl<C, typename C::value_type>::pop_ret(c);
  }

}

#endif //XENDBG_POP_HPP
