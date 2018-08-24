//
// Created by Spencer Michaels on 8/19/18.
//

#ifndef XENDBG_ACTION_HPP
#define XENDBG_ACTION_HPP

#include <functional>

namespace xd::repl {

  class REPL;

  namespace cmd {

    using Action = std::function<void(REPL&)>;

  }

}

#endif //XENDBG_ACTION_HPP
