//
// Created by Spencer Michaels on 10/1/18.
//

#ifndef XENDBG_GDBSTEPCONTINUEREQUEST_HPP
#define XENDBG_GDBSTEPCONTINUEREQUEST_HPP

#include "GDBRequestBase.hpp"

#define DECLARE_SIGNAL_REQUESTS(name1, ch1, name2, ch2) \
  DECLARE_SIMPLE_REQUEST(name1, ch1); \
  class name2 : public GDBRequestBase { \
  public: \
    explicit name2(const std::string &data) \
      : GDBRequestBase(data, ch2), _signal(0) \
    { \
      _signal = read_byte(); \
      expect_end(); \
    }; \
    uint8_t get_signal() { return _signal; }; \
  private: \
    uint8_t _signal; \
  }

namespace xd::gdb::req {

  DECLARE_SIGNAL_REQUESTS(ContinueRequest, 'c', ContinueSignalRequest, 'C');
  DECLARE_SIGNAL_REQUESTS(StepRequest, 's', StepSignalRequest, 'S');

}

#endif //XENDBG_GDBSTEPCONTINUEREQUEST_HPP
