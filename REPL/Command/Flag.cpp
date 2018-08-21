//
// Created by Spencer Michaels on 8/20/18.
//

#include "Flag.hpp"

#include "../../Util/string.hpp"

using xd::util::string::next_char;
using xd::util::string::next_not_char;
using xd::util::string::next_whitespace;
using xd::util::string::skip_whitespace;
using xd::repl::cmd::Flag;

Flag::Flag(char short_name, std::string long_name, std::string description,
    std::vector<Argument> args)
  : _short_name(short_name), _long_name(std::move(long_name)),
    _description(std::move(description)), _args(std::move(args))
{
  if (next_whitespace(_long_name.begin(), _long_name.end()) != _long_name.end())
    throw std::runtime_error("Flag name cannot contain whitespace!");
  if (next_char(_long_name.begin(), _long_name.end(), '-') == _long_name.begin())
    throw std::runtime_error("Flag name cannot start with a '-' character!");
}

std::string::const_iterator Flag::match(std::string::const_iterator begin, std::string::const_iterator end) const {
  auto flag_start = next_not_char(begin, end, '-');

  if (flag_start == begin)
    return begin;

  const auto next_ws = next_whitespace(flag_start, end);

  // Short flag: -f
  if (flag_start == begin+1) {
    if (flag_start == next_ws && !_short_name)
      return next_ws; // Empty short flag: -
    if (*flag_start == _short_name)
      return flag_start+1; // Matched short flag
    return begin;
  }

  // Long flag: --flag
  if (flag_start == begin+2) {
    if (flag_start == next_ws && _long_name.empty())
      return next_ws; // Empty long flag: --
    if (_long_name.size() == (next_ws - flag_start) && std::equal(
        _long_name.begin(), _long_name.end(), flag_start, next_ws))
      return next_ws;
  }

  return begin;
}
