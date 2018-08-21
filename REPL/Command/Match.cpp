//
// Created by Spencer Michaels on 8/20/18.
//

#include "Match.hpp"
#include "../../Util/string.hpp"

using xd::repl::cmd::Argument;
using xd::repl::cmd::Flag;
using xd::repl::cmd::ArgsHandle;
using xd::repl::cmd::FlagsHandle;
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

    auto arg_end = arg.match(it, end);
    if (arg_end == it) {
      auto default_value = arg.get_default_value();
      if (default_value.empty()) {
        throw std::runtime_error("Failed to match arg!");
      } else {
        args_handle.put(arg, default_value);
      }
    } else {
      args_handle.put(arg, std::string(it, arg_end));
    }

    it = arg_end;
  }

  return std::make_pair(it, args_handle);
}

std::pair<StrConstIt, FlagsHandle> xd::repl::cmd::match_flags(
    StrConstIt begin, StrConstIt end, const std::vector<Flag> &flags)
{
  FlagsHandle flags_handle;

  auto it = skip_whitespace(begin, end);
  while (it != end && *it == '-') {
    auto matched_flag = flags.end();
    for (auto flag_it = flags.begin(); flag_it != flags.end(); ++flag_it) {
      auto [args_end, args] = flag_it->match(it, end);
      if (args_end != it) {
        matched_flag = flag_it;
        flags_handle.put(*matched_flag, args);
        it = skip_whitespace(args_end, end);
        break;
      }
    }
    if (matched_flag == flags.end())
      throw std::runtime_error("Unknown flag!");

  }

  return std::make_pair(it, flags_handle);
}
