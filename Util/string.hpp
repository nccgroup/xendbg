//
// Created by Spencer Michaels on 8/19/18.
//

#ifndef XENDBG_UTIL_STRING_HPP
#define XENDBG_UTIL_STRING_HPP

#include <algorithm>
#include <string>

namespace xd::util::string {

  using StrConstIt = std::string::const_iterator;

  StrConstIt skip_whitespace(StrConstIt begin, StrConstIt end) {
    return std::find_if_not(begin, end, std::iswspace);
  };

  StrConstIt expect(const std::string& target, StrConstIt begin, StrConstIt end) {
    if ((end - begin) >= target.size() &&
        std::equal(target.begin(), target.end(), begin, end))
      return begin + target.size();

    return end;
  }

}

#endif //XENDBG_STRING_HPP
