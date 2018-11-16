#ifndef XENDBG_WATCHPOINT_TYPE_HPP
#define XENDBG_WATCHPOINT_TYPE_HPP

namespace xd::dbg {

  enum class WatchpointType {
    Read,
    Write,
    Access, // RWX
  };

}

#endif //XENDBG_WATCHPOINT_TYPE_HPP
