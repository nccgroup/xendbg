//
// Created by Spencer Michaels on 8/20/18.
//

#ifndef XENDBG_MATCH_HPP
#define XENDBG_MATCH_HPP

#include "ArgsHandle.hpp"
#include "Argument.hpp"
#include "Flag.hpp"
#include "FlagsHandle.hpp"

namespace xd::repl::cmd {

  void validate_default_args(const std::vector<Argument> &args);

  std::pair<ArgsHandle, std::string::const_iterator> match_args(
      std::string::const_iterator begin, std::string::const_iterator end,
      const std::vector<Argument> &args);

  std::pair<FlagsHandle, std::string::const_iterator> match_flags(
      std::string::const_iterator begin, std::string::const_iterator end,
      const std::vector<Flag> &flags);
}

#endif //XENDBG_MATCH_HPP
