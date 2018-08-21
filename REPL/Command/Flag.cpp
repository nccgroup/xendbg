//
// Created by Spencer Michaels on 8/20/18.
//

#include "Flag.hpp"
#include "Match.hpp"
#include "../../Util/string.hpp"

using xd::util::string::next_char;
using xd::util::string::next_not_char;
using xd::util::string::next_whitespace;
using xd::util::string::skip_whitespace;
using xd::repl::cmd::ArgsHandle;
using xd::repl::cmd::Flag;
using xd::repl::cmd::match_args;

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

std::pair<ArgsHandle, std::string::const_iterator> Flag::match(std::string::const_iterator begin, std::string::const_iterator end) const {
  auto flag_start = next_not_char(begin, end, '-');

  if (flag_start == begin)
    return std::make_pair(ArgsHandle(), begin);

  const auto next_ws = next_whitespace(flag_start, end);

  // Short flag: -f
  auto flag_end = begin;
  if (flag_start == begin+1) {
    if (flag_start == next_ws && !_short_name)
      flag_end = next_ws;       // Empty short flag: -
    else if (*flag_start == _short_name)
      flag_end = flag_start+1;  // Matched short flag
    else
      return std::make_pair(ArgsHandle(), begin);
  }

  // Long flag: --flag
  else if (flag_start == begin+2) {
    if (flag_start == next_ws && _long_name.empty())
      flag_end = next_ws;  // Empty long flag: --
    else if (_long_name.size() == (size_t)(next_ws - flag_start) && std::equal(
        _long_name.begin(), _long_name.end(), flag_start, next_ws))
      flag_end = next_ws;  // Matched long flag
    else
      return std::make_pair(ArgsHandle(), begin);
  }

  return match_args(flag_end, end, _args);
}
