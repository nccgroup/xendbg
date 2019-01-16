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

#include "Match.hpp"
#include "Verb.hpp"
#include <Util/IndentHelper.hpp>
#include <Util/string.hpp>

using xd::repl::cmd::Action;
using xd::repl::cmd::ArgsHandle;
using xd::repl::cmd::FlagsHandle;
using xd::repl::cmd::validate_args;
using xd::repl::cmd::validate_new_arg;
using xd::repl::cmd::Verb;
using xd::util::IndentHelper;
using xd::util::string::expect;
using xd::util::string::next_whitespace;
using xd::util::string::skip_whitespace;

Verb::Verb(std::string name, std::string description,
           std::vector<Flag> flags, std::vector<Argument> args,
           MakeActionFn make_action)
  : _name(std::move(name)), _description(std::move(description)),
    _flags(std::move(flags)), _args(std::move(args)),
    _make_action(std::move(make_action))
{
    validate_args(_args);
};

void Verb::print(std::ostream& out, IndentHelper& indent) const {
  out << indent << _name;

  const bool has_args = !_args.empty();
  const bool has_flags = !_flags.empty();

  if (!has_args && !has_flags) {
    out << ": " << _description << std::endl;
  } else {
    if (has_flags) {
      out << " [flags]";
    }

    for (const auto& arg : _args) {
      out << " ";
      arg.print(out, indent);
    }

    const size_t indent_level = has_flags ? 2 : 1;
    indent.indent(indent_level);
    out << std::endl;
    out << indent << _description << std::endl;
    indent.unindent(indent_level);
  }

  indent.indent();
  for (const auto& flag : _flags) {
    flag.print(out, indent);
  }
  indent.unindent();
}

void Verb::add_arg(Argument arg) {
  validate_new_arg(_args, arg);
  _args.push_back(arg);
}

std::string::const_iterator Verb::match_name(
        std::string::const_iterator begin, std::string::const_iterator end) const
{
  const auto name_end = expect(_name, begin, end);

  if (name_end == begin)
    return begin;

  return name_end;
}

std::optional<Action> Verb::match(std::string::const_iterator begin,
    std::string::const_iterator end) const
{
  const auto name_end = match_name(begin, end);

  if (name_end == begin)
    return std::nullopt;

  auto [flags_end, flags] = match_flags(skip_whitespace(name_end , end), end);
  auto [args_end, args] = match_args(skip_whitespace(flags_end, end), end);

  const auto next_non_ws = skip_whitespace(args_end, end);
  if (next_non_ws != end)
    // TODO
    throw ExtraArgumentException("Extra arg(s): " + std::string(next_non_ws, end));

  return _make_action(flags, args);
}

std::optional<std::vector<std::string>> Verb::complete(
    std::string::const_iterator begin, std::string::const_iterator end) const
{
  const auto name_end = match_name(begin, end);

  if (name_end == begin)
    return std::nullopt;
  
  // Parse out flags to figure out which ones are left to autocomplete
  try {
    auto [flags_end, flags] = xd::repl::cmd::match_flags(
        skip_whitespace(name_end, end), end, _flags, true);

    std::vector<std::string> options;

    const auto next_arg_and_pos = get_next_arg(
        skip_whitespace(flags_end, end), end, _args);
    if (next_arg_and_pos) {
      const auto [pos, next_arg] = next_arg_and_pos.value();
      auto arg_options = next_arg.complete(pos, end);
      if (arg_options)
        options.swap(arg_options.value());
    }

    for (const auto &flag : _flags) {
      if (!flags.has(flag.get_short_name())) {
        options.push_back(std::string("-") + flag.get_short_name());
        options.push_back("--" + flag.get_long_name());
      }
    }
    return options;

  } catch (const FlagArgMatchFailedException &e) {
    const auto post_arg = skip_whitespace(next_whitespace(e.get_pos(), end), end);
    if (post_arg == end)
      return e.get_argument().complete(e.get_pos(), end);
    return std::vector<std::string>();
  }
}

std::pair<std::string::const_iterator, FlagsHandle> Verb::match_flags(
    std::string::const_iterator begin, std::string::const_iterator end) const
{
  return xd::repl::cmd::match_flags(begin, end, _flags);
}

std::pair<std::string::const_iterator, ArgsHandle> Verb::match_args(
    std::string::const_iterator begin, std::string::const_iterator end) const
{
  return xd::repl::cmd::match_args(begin, end, _args);
}
