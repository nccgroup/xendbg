//
// Created by Spencer Michaels on 8/20/18.
//

#include "Flag.hpp"

#include "../../Util/string.hpp"

using xd::util::string::next_not_char;
using xd::util::string::next_whitespace;
using xd::util::string::skip_whitespace;
using xd::repl::cmd::Flag;

std::string::const_iterator Flag::match(std::string::const_iterator begin, std::string::const_iterator end) const {
  auto next = next_not_char(begin, end, '-');

  if (next == begin)
    return begin;

  // Short flag
  if (next == begin+1) {
    if (!_short_name)
      return end;
  }

  // Long flag
  if (next == begin+2) {
    if (_long_name.empty())
  }

  return begin;

  // \-$
  if (begin+1 == end && !_short_name)
    return end;
  // \--$
  if (*(begin+1) == '-' && begin+2 == end && _long_name.empty())
    return end;

  auto it = n

  const auto next_ws = next_whitespace(begin, end);
}
