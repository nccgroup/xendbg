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

#ifndef XENDBG_UTIL_STRING_HPP
#define XENDBG_UTIL_STRING_HPP

#include <string>

namespace xd::util::string {

  using StrConstIt = std::string::const_iterator;

  template <typename It_t>
  It_t next_char(It_t begin, It_t end, char c) {
    return std::find(begin, end, c);
  };

  template <typename It_t>
  It_t next_not_char(It_t begin, It_t end, char c) {
    return std::find_if(begin, end, [c](auto& sc) { return sc != c; });
  };

  template <typename It_t>
  It_t next_whitespace(It_t begin, It_t end) {
    return std::find_if(begin, end, std::iswspace);
  };

  template <typename It_t>
  It_t skip_whitespace(It_t begin, It_t end) {
      return std::find_if_not(begin, end, std::iswspace);
  };

  template <typename It_t>
  It_t match_optionally_quoted_string(It_t begin, It_t end) {
    if (begin == end)
      return begin;

    const char delimiter = *begin;
    if (delimiter == '"' || delimiter == '\'') {
      const auto new_end = std::find(begin, end, delimiter);
      if (new_end == end)
        return begin;

      return new_end+1;
    }

    // Bash-like behavior: if no quotes, just go up to the next whitespace
    auto new_end = util::string::next_whitespace(begin, end);
    return new_end;
  }

  template <typename It_t>
  bool is_prefix(It_t target_begin, It_t target_end, It_t begin, It_t end) {
    const auto target_size = (target_end - target_begin);
    auto new_end = begin + target_size;
    return ((end - begin) >= target_size &&
      std::equal(target_begin, target_end, begin, new_end));
  }

  template <typename Str1_t, typename Str2_t>
  bool is_prefix(const Str1_t &s1, const Str2_t &s2) {
    return is_prefix(s1.begin(), s1.end(), s2.begin(), s2.end());
  }

  template <typename It_t, typename Str_t>
  bool is_prefix(const Str_t &target, It_t begin, It_t end) {
    return is_prefix(target.begin(), target.end(), begin, end);
  }

  template <typename It_t>
  It_t expect(const std::string& target, It_t begin, It_t end) {
    const auto first_non_ws = skip_whitespace(begin, end);
    const auto next_ws = next_whitespace(first_non_ws, end);
    if (std::equal(target.begin(), target.end(), first_non_ws, next_ws)) {
      return next_ws;
    };
    return begin;
  }
}

#endif //XENDBG_STRING_HPP
