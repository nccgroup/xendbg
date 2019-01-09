//
// Copyright (C) 2018-2019 Spencer Michaels
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

//
// Created by Spencer Michaels on 8/20/18.
//

#include "Flag.hpp"
#include "Match.hpp"
#include <Util/IndentHelper.hpp>
#include <Util/string.hpp>

using xd::repl::cmd::Argument;
using xd::repl::cmd::ArgsHandle;
using xd::repl::cmd::Flag;
using xd::repl::cmd::FlagArgMatchFailedException;
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
    throw FlagNameException("Flag name cannot contain whitespace!");
  if (next_char(_long_name.begin(), _long_name.end(), '-') == _long_name.begin())
    throw FlagNameException("Flag name cannot start with a '-' character!");
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
  begin = skip_whitespace(begin, end);
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
  }

  // Long flag: --flag
  else if (flag_start == begin+2) {
    if (flag_start == next_ws && _long_name.empty())
      return next_ws;  // Empty long flag: --
    else if (_long_name.size() == (size_t)(next_ws - flag_start) && std::equal(
        _long_name.begin(), _long_name.end(), flag_start, next_ws))
      return next_ws;  // Matched long flag
  }

  return begin;
}

std::pair<std::string::const_iterator, ArgsHandle> Flag::match(
    std::string::const_iterator begin, std::string::const_iterator end) const
{
  const auto args_begin = match_name(begin, end);
  if (args_begin == begin)
    return std::make_pair(begin, ArgsHandle());

  try {
    return match_args(args_begin, end, _args);
  } catch (const ArgMatchFailedException &e) {
    throw FlagArgMatchFailedException(e.get_pos(), *this, e.get_argument());
  }
}

std::optional<std::pair<std::string::const_iterator, Argument>>
Flag::get_next_arg(
    std::string::const_iterator begin, std::string::const_iterator end) const
{
  const auto name_end = match_name(begin, end);
  if (name_end == begin)
    return std::nullopt;

  return xd::repl::cmd::get_next_arg(skip_whitespace(name_end, end), end, _args);
}
