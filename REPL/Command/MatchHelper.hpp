//
// Created by Spencer Michaels on 8/29/18.
//

#ifndef XENDBG_MATCHHELPER_HPP
#define XENDBG_MATCHHELPER_HPP

#include <string>

namespace xd::repl::cmd::match {

  std::string::const_iterator match_everything(std::string::const_iterator begin, std::string::const_iterator end);

}

#endif //XENDBG_MATCHHELPER_HPP
