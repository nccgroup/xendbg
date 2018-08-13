//
// Created by Spencer Michaels on 8/12/18.
//

#ifndef XENDBG_REPL_HPP
#define XENDBG_REPL_HPP

#include <string>

namespace repl {

  void set_prompt(const std::string& prompt);
  void do_repl();

}

#endif //XENDBG_REPL_HPP
