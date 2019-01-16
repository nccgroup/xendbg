//
// Copyright (C) 2018-2019 NCC Group
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
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
