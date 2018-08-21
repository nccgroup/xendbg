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

std::pair<ArgsHandle, StrConstIt> xd::repl::cmd::match_args(
    StrConstIt begin, StrConstIt end, const std::vector<Argument> &args)
{
  ArgsHandle args_handle;

  auto it = begin;
  for (const auto& arg : args) {
    it = skip_whitespace(it, end);

    auto arg_end = arg.match(it, end);
    if (arg_end == it)
      throw std::runtime_error("failed to match arg!");

    args_handle.put(arg, std::string(it, arg_end));
    it = arg_end;
  }

  return std::make_pair(args_handle, it);
}

std::pair<FlagsHandle, StrConstIt> xd::repl::cmd::match_flags(
    StrConstIt begin, StrConstIt end, const std::vector<Flag> &flags)
{
  FlagsHandle flags_handle;

  auto it = skip_whitespace(begin, end);
  auto matched_flag = flags.end();
  while (it != end && *it == '-') {
    for (auto flag_it = flags.begin(); flag_it != flags.end(); ++flag_it) {
      auto match_pos = flag_it->match(it, end);
      if (match_pos != it) {
        matched_flag = flag_it;
        it = match_pos;
        break;
      }
    }

    if (matched_flag == flags.end())
      throw std::runtime_error("unknown flag!");

    const auto& flag = *matched_flag;

    auto [args, args_end] = match_args(it, end);
    flags_handle.put(flag, args);

    it = skip_whitespace(args_end, end);
  }

  return std::make_pair(flags_handle, it);
}
