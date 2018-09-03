//
// Created by Spencer Michaels on 8/29/18.
//

#ifndef XENDBG_MATCHHELPER_HPP
#define XENDBG_MATCHHELPER_HPP

#include <functional>
#include <string>
#include <vector>

namespace xd::repl::cmd::match {
  using MatcherFn = std::function<std::string::const_iterator(
      std::string::const_iterator, std::string::const_iterator)>;

  std::string::const_iterator match_everything(
      std::string::const_iterator begin, std::string::const_iterator end);

  MatcherFn make_match_one_of(std::vector<std::string> options);

}

#endif //XENDBG_MATCHHELPER_HPP
