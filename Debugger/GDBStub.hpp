//
// Created by Spencer Michaels on 9/5/18.
//

#ifndef XENDBG_GDBSTUB_HPP
#define XENDBG_GDBSTUB_HPP

namespace xd::debugger {

  class GDBStub {
  public:
    void run(int port);
  };

}


#endif //XENDBG_GDBSTUB_HPP
