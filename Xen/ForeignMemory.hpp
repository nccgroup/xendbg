//
// Created by Spencer Michaels on 8/13/18.
//

#ifndef XENDBG_FOREIGNMEMORY_HPP
#define XENDBG_FOREIGNMEMORY_HPP

#include <memory>

struct xenforeignmemory_handle;

namespace xd::xen {

  class ForeignMemory {
  public:
    ForeignMemory();

  private:
    std::unique_ptr<xenforeignmemory_handle> _foreign_memory;
  };

}

#endif //XENDBG_FOREIGNMEMORY_HPP
