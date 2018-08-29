//
// Created by Spencer Michaels on 8/20/18.
//

#include "Argument.hpp"
#include "../../Util/IndentHelper.hpp"
#include "../../Util/string.hpp"

using xd::repl::cmd::Argument;
using xd::util::IndentHelper;

void Argument::print(std::ostream& out, IndentHelper& /*indent*/) const {
  if (_is_optional) {
    out
      << "["
      << _name;
    if (!_default_value.empty()) {
      out
        << "="
        << _default_value;
    }
    out << "]";
  } else {
    out
      << "<"
      << _name
      << ">";
  }
}
