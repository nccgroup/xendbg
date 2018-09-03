//
// Created by Spencer Michaels on 8/20/18.
//

#include <iostream>

#include "Match.hpp"
#include "../../Util/string.hpp"

using xd::repl::cmd::Argument;
using xd::repl::cmd::Flag;
using xd::repl::cmd::ArgsHandle;
using xd::repl::cmd::FlagsHandle;
using xd::util::string::is_prefix;
using xd::util::string::next_char;
using xd::util::string::next_not_char;
using xd::util::string::next_whitespace;
using xd::util::string::skip_whitespace;
using xd::util::string::StrConstIt ;

void xd::repl::cmd::validate_args(const std::vector<Argument> &args) {
  bool prev_arg_has_default = false;
  for (const auto& arg : args) {
    if (arg.get_default_value().empty()) {
      if (prev_arg_has_default) {
        throw DefaultArgPositionException();
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
    throw DefaultArgPositionException();
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
        throw ArgMatchFailedException(it, arg);
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

  auto it = begin;
  while (it != end && *it == '-') {
    const auto flag_it = std::find_if(flags.begin(), flags.end(),
      [it, end](const auto &flag) {
        return flag.match_name(it, end) != it;
      });

    if (flag_it != flags.end()) {
      const auto [args_end, args] = flag_it->match(it, end);
      flags_handle.put(*flag_it, args);
      it = skip_whitespace(args_end, end);
    } else {
      if (ignore_unknown_flags) {
        // Find the next potential flag
        // If this is the last potential flag, skip beyond it and bail out
        const auto prev_it = it;
        it = next_char(it, end, '-');
        if (it == prev_it) {
          return std::make_pair(next_whitespace(it+1, end), flags_handle);
        } else if (it == prev_it+1 && it == next_char(it, end, '-')) {
          return std::make_pair(next_whitespace(it+2, end), flags_handle);
        }
      } else {
        throw UnknownFlagException(it);
      }
    }
  }

  return std::make_pair(it, flags_handle);
}

std::optional<std::pair<std::string::const_iterator, Argument>> 
xd::repl::cmd::get_next_arg(StrConstIt begin, StrConstIt end,
    const std::vector<Argument> &args)
{
  auto it = begin;
  for (const auto& arg : args) {
    // If the arg fails to match, it is the next expected arg.
    const auto arg_end = arg.match(it, end);
    if (arg_end == it)
      return std::make_pair(it, arg);

    /*
     * If the arg has completion options AND the current string is a strict
     * prefix of at least one of its options, then it is the next expected.
     */
    const auto options = arg.complete(it, end);
    if (options) {
      const auto has_partial_match = std::any_of(
          options.value().begin(), options.value().end(),
          [it, arg_end](const auto &opt) {
            return (arg_end - it < opt.size()) &&
              is_prefix(it, arg_end, opt.begin(), opt.end());
          });

      if (has_partial_match)
        return std::make_pair(it, arg);
    }

    it = skip_whitespace(arg_end, end);
  }

  // All args accounted for!
  return std::nullopt;
}
