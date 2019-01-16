//
// Copyright (C) 2018-2019 NCC Group
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

#include <sstream>

#include "Argument.hpp"
#include <Util/IndentHelper.hpp>
#include <Util/string.hpp>

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
