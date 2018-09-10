//
// Created by Spencer Michaels on 9/10/18.
//

#ifndef XENDBG_REGISTERS_HPP
#define XENDBG_REGISTERS_HPP

#include <cstdint>

namespace reg {

  template <typename Value_t>
  struct Register {
    using Value = Value_t;
    Value_t value;
  };

}

#define DECLARE_REGISTER_ALTNAME(_name, _alt_name, _type) \
  struct _name : public reg::Register<_type> { \
    static constexpr auto name = "_name"; \
    static constexpr auto alt_name = "_alt_name"; \
}

#define DECLARE_REGISTER(_name, _type) \
  DECLARE_REGISTER_ALTNAME(_name, nullptr, _type)

#endif //XENDBG_REGISTERS_HPP
