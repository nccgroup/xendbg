 //
// Created by Spencer Michaels on 8/19/18.
//

#include "Match.hpp"
#include "Verb.hpp"
#include "../../Util/IndentHelper.hpp"
#include "../../Util/string.hpp"

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

std::optional<Action> Verb::match(std::string::const_iterator begin,
    std::string::const_iterator end) const
{
  const auto flags_start = match_prefix_skipping_whitespace(begin, end);

  if (flags_start == begin) {
    return std::nullopt;
  }

  auto [flags_end, flags] = match_flags(flags_start, end);
  auto [args_end, args] = match_args(flags_end, end);

  if (args_end != end)
    throw std::runtime_error("Unknown arg(s): " + std::string(args_end, end)); // TODO

  return _make_action(flags, args);
}

std::optional<std::vector<std::string>> Verb::complete(
    std::string::const_iterator begin, std::string::const_iterator end) const
{
  const auto flags_start = match_prefix_skipping_whitespace(begin, end);

  if (flags_start == begin) {
    return std::nullopt;
  }

  // Parse out flags to figure out which ones are left to autocomplete
  auto [_, flags] = xd::repl::cmd::match_flags(flags_start, end, _flags, true);

  std::vector<std::string> options;
  for (const auto &flag : _flags) {
    if (!flags.has(flag.get_short_name())) {
      options.push_back(std::string("-") + flag.get_short_name());
      options.push_back("--" + flag.get_long_name());
    }
  }

  return options;
}

std::string::const_iterator Verb::match_prefix_skipping_whitespace(
        std::string::const_iterator begin, std::string::const_iterator end) const
{
  const auto first_non_ws = skip_whitespace(begin, end);
  const auto start = expect(_name, first_non_ws, end);

  if (start == first_non_ws)
    return begin;

  return start;
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
