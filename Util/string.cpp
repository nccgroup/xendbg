#include <algorithm>
#include <cwctype>

#include "string.hpp"

using xd::util::string::StrConstIt;

StrConstIt xd::util::string::expect(const std::string& target, StrConstIt begin, StrConstIt end) {
  auto new_end = begin + target.size();
  if ((size_t)(end - begin) >= target.size() &&
    std::equal(target.begin(), target.end(), begin, new_end))
    return new_end;
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
