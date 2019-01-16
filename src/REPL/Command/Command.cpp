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

#include <iostream>

#include "Command.hpp"
#include <Util/IndentHelper.hpp>
#include <Util/string.hpp>

using xd::util::IndentHelper;
using xd::util::string::expect;
using xd::util::string::skip_whitespace;
using xd::repl::cmd::Action;
using xd::repl::cmd::Command;

void Command::print(std::ostream& out, IndentHelper& indent) const {
  out << indent
    << get_name()
    << ": "
    << get_description()
    << std::endl;

  indent.indent();
  for (const auto& verb : _verbs) {
    verb.print(out, indent);
  }
  indent.unindent();
}

std::optional<Action> Command::match(std::string::const_iterator begin, std::string::const_iterator end) const {
  const auto name_end = expect(get_name(), begin, end);

  if (name_end == begin)
    return std::nullopt;

  for (const auto& verb : _verbs) {
    auto action = verb.match(name_end, end);
    if (action)
      return action;
  }

  return std::nullopt;
}

std::optional<std::vector<std::string>> Command::complete(std::string::const_iterator begin, std::string::const_iterator end) const {
  const auto name_end = expect(get_name(), begin, end);

  // If s doesn't have this command as a prefix, neither this command
  // nor its children have any relevant completion options to give
  if (name_end == begin)
    return std::nullopt;

  // If a verb has more specific completion options, return those instead
  for (const auto& verb : _verbs) {
    auto options = verb.complete(name_end, end);

    if (options)
      return options;
  }

  // Otherwise return the list of verbs
  std::vector<std::string> options;
  options.reserve(_verbs.size());
  std::transform(_verbs.begin(), _verbs.end(), std::back_inserter(options),
    [](auto& verb) {
      return verb.get_name();
    });

  return options;
}
