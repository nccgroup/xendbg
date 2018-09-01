#include <algorithm>
#include <cwctype>
#include <iostream>

#include "string.hpp"

using xd::util::string::StrConstIt;

bool xd::util::string::is_prefix(
    StrConstIt target_begin, StrConstIt target_end,
    StrConstIt begin, StrConstIt end)
{
  const auto target_size = (target_end - target_begin);
  auto new_end = begin + target_size;
  return ((end - begin) >= target_size &&
    std::equal(target_begin, target_end, begin, new_end));
}

StrConstIt xd::util::string::expect(const std::string& target, StrConstIt begin, StrConstIt end) {
  const auto first_non_ws = skip_whitespace(begin, end);
  const auto next_ws = next_whitespace(first_non_ws, end);
  if (std::equal(target.begin(), target.end(), first_non_ws, next_ws)) {
    return next_ws;
  };
  return begin;
}

StrConstIt xd::util::string::next_char(StrConstIt begin, StrConstIt end, char c) {
  return std::find(begin, end, c);
};

StrConstIt xd::util::string::next_not_char(StrConstIt begin, StrConstIt end, char c) {
  return std::find_if(begin, end, [c](auto& sc) { return sc != c; });
};

StrConstIt xd::util::string::next_whitespace(StrConstIt begin, StrConstIt end) {
  return std::find_if(begin, end, std::iswspace);
};

StrConstIt xd::util::string::skip_whitespace(StrConstIt begin, StrConstIt end) {
    return std::find_if_not(begin, end, std::iswspace);
};

StrConstIt xd::util::string::match_optionally_quoted_string(StrConstIt begin, StrConstIt end) {
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
