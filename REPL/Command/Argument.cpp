//
// Created by Spencer Michaels on 8/20/18.
//

#include <sstream>

#include "Argument.hpp"
#include "../../Util/IndentHelper.hpp"
#include "../../Util/string.hpp"

using xd::repl::cmd::Argument;
using xd::util::IndentHelper;

void Argument::print(std::ostream& out, IndentHelper& /*indent*/) const {
  /*
  const auto print_completion_options = [this](std::ostream &out) {
    if (_completer) {
      const std::string dummy_input = "";
      const auto options_opt = _completer(dummy_input.end(), dummy_input.end());

      if (!options_opt || options_opt.value().empty())
        return;
      const auto options = options_opt.value();

      std::ostringstream ss;
      for (const auto &opt : options) {
        ss << opt << ",";
      }

      out
        << "={"
        << ss.str()
        << "}";
    }
  };
  */

  const auto print_default_value = [this](std::ostream &out) {
    if (!_default_value.empty()) {
      out
        << "="
        << _default_value;
    }
  };

  if (_is_optional) {
    out
      << "["
      << _name;
    //print_completion_options(out);
    print_default_value(out);
    out << "]";
  }
  if (_completer) {
    out
      << "<"
      << _name;
    //print_completion_options(out);
    out << ">";
  } else {
    out
      << "<"
      << _name
      << ">";
  }
}
