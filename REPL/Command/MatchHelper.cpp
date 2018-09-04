//
// Created by Spencer Michaels on 8/29/18.
//

#include <iostream>

#include "MatchHelper.hpp"
#include "../../Util/string.hpp"

using xd::repl::cmd::match::MatcherFn;
using xd::util::string::next_whitespace;
using xd::util::string::skip_whitespace;

using StrConstIt = std::string::const_iterator;

StrConstIt xd::repl::cmd::match::match_everything(StrConstIt /*begin*/, StrConstIt end) {
  return end;
}

StrConstIt xd::repl::cmd::match::match_number_unsigned(StrConstIt begin, StrConstIt end) {
  begin = skip_whitespace(begin, end);
  const auto ws = next_whitespace(begin, end);

  try {
    std::stoul(std::string(begin, ws));
    return ws;
  } catch (const std::invalid_argument &e) {
    return begin;
  }
}

MatcherFn xd::repl::cmd::match::make_match_one_of(std::vector<std::string> options) {
  return [options](std::string::const_iterator begin, std::string::const_iterator end) {
    size_t len = 0;
    std::find_if(options.begin(), options.end(),
        [begin, end, &len](const auto& opt) {
          if (util::string::is_prefix(opt.begin(), opt.end(), begin, end)) {
            len = opt.size();
            return true;
          }
          return false;
        });

    return begin + len;
  };
}
