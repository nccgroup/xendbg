#include <algorithm>
#include <cwctype>

#include "string.hpp"

using xd::util::string::StrConstIt;

StrConstIt xd::util::string::skip_whitespace(StrConstIt begin, StrConstIt end) {
    return std::find_if_not(begin, end, std::iswspace);
};

StrConstIt xd::util::string::expect(const std::string& target, StrConstIt begin, StrConstIt end) {
  auto new_end = begin + target.size();
  if ((size_t)(end - begin) >= target.size() &&
    std::equal(target.begin(), target.end(), begin, new_end))
  return new_end;

  return begin;
}