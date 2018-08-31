//
// Created by Spencer Michaels on 8/20/18.
//

#include "Match.hpp"
#include "../../Util/string.hpp"

using xd::repl::cmd::Argument;
using xd::repl::cmd::Flag;
using xd::repl::cmd::ArgsHandle;
using xd::repl::cmd::FlagsHandle;
using xd::util::string::next_char;
using xd::util::string::next_whitespace;
using xd::util::string::skip_whitespace;
using xd::util::string::StrConstIt ;

void xd::repl::cmd::validate_args(const std::vector<Argument> &args) {
  bool prev_arg_has_default = false;
  for (const auto& arg : args) {
    if (arg.get_default_value().empty()) {
      if (prev_arg_has_default) {
        throw std::runtime_error("Args with defaults must come at the end of the args list!");
      }
    } else {
      prev_arg_has_default = true;
    }
  }
}

void xd::repl::cmd::validate_new_arg(const std::vector<Argument> &args,
      const Argument &new_arg)
{
  if (!args.empty() &&
      !args.back().get_default_value().empty() &&
      new_arg.get_default_value().empty())
  {
    throw std::runtime_error("Args with defaults come at the end of the args list!");
  }
}

std::pair<StrConstIt, ArgsHandle> xd::repl::cmd::match_args(
    StrConstIt begin, StrConstIt end, const std::vector<Argument> &args)
{
  ArgsHandle args_handle;

  auto it = begin;
  for (const auto& arg : args) {
    it = skip_whitespace(it, end);

    const auto arg_end = arg.match(it, end);
    if (arg_end == it) {
      if (!arg.is_optional()) {
        throw std::runtime_error("Failed to match arg!");
      } else {
        args_handle.put(arg, arg.get_default_value());
      }
    } else {
      args_handle.put(arg, std::string(it, arg_end));
    }

    it = arg_end;
  }

  return std::make_pair(it, args_handle);
}

std::pair<StrConstIt, FlagsHandle> xd::repl::cmd::match_flags(
    StrConstIt begin, StrConstIt end, const std::vector<Flag> &flags,
    bool ignore_unknown_flags)
{
  FlagsHandle flags_handle;

  auto it = skip_whitespace(begin, end);
  while (it != end && *it == '-') {
    const auto flag_it = std::find_if(flags.begin(), flags.end(),
        [it, end](const auto &flag) {
          return flag.match_name(it, end) != it;
        });

    if (flag_it == flags.end()) {
      if (ignore_unknown_flags) {
        // Find the next potential flag
        const auto prev_it = it;
        it = next_char(it, end, '-');
        // If this is the last potential flag, skip beyond it and bail out
        if (it == prev_it) {
          it = next_whitespace(it, end);
          return std::make_pair(it, flags_handle);
        }
      } else {
        const auto next_ws = next_whitespace(it, end);
        throw std::runtime_error("Unknown flag '" + std::string(it, next_ws) + "'!");
      }
    }

    const auto [args_end, args] = flag_it->match(it, end);
    if (args_end != it) {
      flags_handle.put(*flag_it, args);
      it = skip_whitespace(args_end, end);
    }
  }

  return std::make_pair(it, flags_handle);
}

std::optional<Argument> xd::repl::cmd::get_next_arg(
    StrConstIt begin, StrConstIt end, const std::vector<Argument> &args)
{
  auto it = begin;
  for (const auto& arg : args) {
    it = skip_whitespace(it, end);

    const auto arg_end = arg.match(it, end);
    if (arg_end == it)
      return arg;

    it = arg_end;
  }

  return std::nullopt;
}
