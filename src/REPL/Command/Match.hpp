//
// Copyright (C) 2018-2019 Spencer Michaels
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

//
// Created by Spencer Michaels on 8/20/18.
//

#ifndef XENDBG_MATCH_HPP
#define XENDBG_MATCH_HPP

#include <stdexcept>

#include "ArgsHandle.hpp"
#include "Argument.hpp"
#include "Flag.hpp"
#include "FlagsHandle.hpp"

namespace xd::repl::cmd {

  class DefaultArgPositionException : public std::exception {};

  class UnknownFlagException : public std::exception {
    public:
      UnknownFlagException(std::string::const_iterator pos)
        : _pos(pos) {};

    std::string::const_iterator get_pos() const { return _pos; }

    private:
      std::string::const_iterator _pos;
  };

  class ArgMatchFailedException : public std::exception {
  public:
    ArgMatchFailedException(std::string::const_iterator pos, Argument arg)
      : _pos(pos), _arg(arg) {};

    std::string::const_iterator get_pos() const { return _pos; }
    const Argument &get_argument() const { return _arg; };
    
  private:
    std::string::const_iterator _pos;
    Argument _arg;
  };

  void validate_args(const std::vector<Argument> &args);
  void validate_new_arg(const std::vector<Argument> &args,
      const Argument &new_arg);

  std::pair<std::string::const_iterator, ArgsHandle> match_args(
      std::string::const_iterator begin, std::string::const_iterator end,
      const std::vector<Argument> &args);

  std::pair<std::string::const_iterator, FlagsHandle> match_flags(
      std::string::const_iterator begin, std::string::const_iterator end,
      const std::vector<Flag> &flags, bool ignore_unknown_flags = false);

  std::optional<std::pair<std::string::const_iterator, Argument>> get_next_arg(
      std::string::const_iterator begin, std::string::const_iterator end,
      const std::vector<Argument> &args);
}

#endif //XENDBG_MATCH_HPP
