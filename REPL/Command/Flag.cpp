//
// Created by Spencer Michaels on 8/20/18.
//

#include "Flag.hpp"
#include "Match.hpp"
#include "../../Util/IndentHelper.hpp"
#include "../../Util/string.hpp"

using xd::repl::cmd::ArgsHandle;
using xd::repl::cmd::Flag;
using xd::repl::cmd::match_args;
using xd::repl::cmd::validate_args;
using xd::repl::cmd::validate_new_arg;
using xd::util::IndentHelper;
using xd::util::string::next_char;
using xd::util::string::next_not_char;
using xd::util::string::next_whitespace;
using xd::util::string::skip_whitespace;

Flag::Flag(char short_name, std::string long_name, std::string description,
    std::vector<Argument> args)
  : _short_name(short_name), _long_name(std::move(long_name)),
    _description(std::move(description)), _args(std::move(args))
{
  if (next_whitespace(_long_name.begin(), _long_name.end()) != _long_name.end())
    throw std::runtime_error("Flag name cannot contain whitespace!");
  if (next_char(_long_name.begin(), _long_name.end(), '-') == _long_name.begin())
    throw std::runtime_error("Flag name cannot start with a '-' character!");
  validate_args(_args);
}

void Flag::print(std::ostream& out, IndentHelper& indent) const {
  out << indent
    << "-" << _short_name
    << "/--" << _long_name;

  for (const auto& arg : _args) {
    out << " ";
    arg.print(out, indent);
  }

  out << std::endl;
  indent.indent();
  out << indent
    << _description
    << std::endl;
  indent.unindent();
}

void Flag::add_arg(Argument arg) {
  validate_new_arg(_args, arg);
  _args.push_back(std::move(arg));
}

std::string::const_iterator Flag::match_name(
    std::string::const_iterator begin, std::string::const_iterator end) const
{
  auto flag_start = next_not_char(begin, end, '-');

  if (flag_start == begin)
    return begin;

  const auto next_ws = next_whitespace(flag_start, end);

  // Short flag: -f
  if (flag_start == begin+1) {
    if (flag_start == next_ws && !_short_name)
      return next_ws;       // Empty short flag: -  TODO: requires space after?
    else if (*flag_start == _short_name)
      return flag_start+1;  // Matched short flag
    else
      return begin;
  }

  // Long flag: --flag
  else if (flag_start == begin+2) {
    if (flag_start == next_ws && _long_name.empty())
      return next_ws;  // Empty long flag: --
    else if (_long_name.size() == (size_t)(next_ws - flag_start) && std::equal(
        _long_name.begin(), _long_name.end(), flag_start, next_ws))
      return next_ws;  // Matched long flag
    else
      return begin;
  }

  return begin;
}

std::pair<std::string::const_iterator, ArgsHandle> Flag::match(
    std::string::const_iterator begin, std::string::const_iterator end) const
{
  const auto args_begin = match_name(begin, end);
  if (args_begin == begin)
    return std::make_pair(begin, ArgsHandle());

  return match_args(args_begin, end, _args);
}
