//
// Created by Spencer Michaels on 8/12/18.
//

#ifndef XENDBG_SENTINEL_HPP
#define XENDBG_SENTINEL_HPP

#include <cstddef>

#include "Expression/Operator/Operator.hpp"
#include "Expression/Operator/Precedence.hpp"

namespace xd::parser::expr::op {
  struct Sentinel : public Operator<Arity::Nullary>;

  template <>
  struct _precedence_impl<Sentinel> {
    static const op::Precedence p = std::numeric_limits<op::Precedence>::min();
  };
}

#endif //XENDBG_SENTINEL_HPP
