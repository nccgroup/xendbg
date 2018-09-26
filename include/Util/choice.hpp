//
// Created by Spencer Michaels on 8/12/18.
//

#ifndef XENDBG_UTIL_CHOICE_HPP
#define XENDBG_UTIL_CHOICE_HPP

namespace xd::util {

  template <bool value, typename IfTrue_t, typename IfFalse_t>
  struct choice;

  template <typename IfTrue_t, typename IfFalse_t>
  struct choice<true, IfTrue_t, IfFalse_t> {
    using type = IfTrue_t;
  };

  template <typename IfTrue_t, typename IfFalse_t>
  struct choice<false, IfTrue_t, IfFalse_t> {
    using type = IfFalse_t;
  };

}

#endif //XENDBG_UTIL_CHOICE_HPP
