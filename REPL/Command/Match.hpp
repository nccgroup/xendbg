//
// Created by Spencer Michaels on 8/20/18.
//

#ifndef XENDBG_MATCH_HPP
#define XENDBG_MATCH_HPP

#include <stdexcept>

#include "ArgsHandle.hpp"
#include "Argument.hpp"
#include "Flag.hpp"
#include "FlagsHandle.hpp"

namespace xd::repl::cmd {

  void validate_args(const std::vector<Argument> &args);
  void validate_new_arg(const std::vector<Argument> &args,
      const Argument &new_arg);

  std::pair<std::string::const_iterator, ArgsHandle> match_args(
      std::string::const_iterator begin, std::string::const_iterator end,
      const std::vector<Argument> &args);

  std::pair<std::string::const_iterator, FlagsHandle> match_flags(
      std::string::const_iterator begin, std::string::const_iterator end,
      const std::vector<Flag> &flags, bool ignore_unknown_flags = false);

  std::optional<Argument> get_next_arg(std::string::const_iterator begin,
      std::string::const_iterator end, const std::vector<Argument> &args);
}

#endif //XENDBG_MATCH_HPP
