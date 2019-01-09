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
// Created by Spencer Michaels on 8/12/18.
//

#ifndef XENDBG_PARSEREXCEPTION_HPP
#define XENDBG_PARSEREXCEPTION_HPP

#include <cstring>
#include <stdexcept>
#include <string>

#include "Token/Symbol.hpp"

#define PARSER_EXCEPTION_BUF_SIZE 0x200

namespace xd::parser::except {

  class SentinelMergeException : public std::exception {
  };

  class ParserException : public std::exception {
  public:
    ParserException(const std::string &input, size_t pos)
        : _input(), _pos(pos) {
      strncpy(_input, input.c_str(), PARSER_EXCEPTION_BUF_SIZE);
    };

    virtual const char *input() const noexcept { return _input; }

    size_t pos() const { return _pos; };

  private:
    char _input[PARSER_EXCEPTION_BUF_SIZE];
    size_t _pos;
  };

  class MissingExpressionException : public ParserException {
  public:
    MissingExpressionException(const std::string &input, size_t pos)
        : ParserException(input, pos) {};
  };

  class ExtraTokenException : public ParserException {
  public:
    ExtraTokenException(const std::string &input, size_t pos)
        : ParserException(input, pos) {};
  };

  class InvalidInputException : public ParserException {
  public:
    InvalidInputException(const std::string &input, size_t pos)
        : ParserException(input, pos) {};
  };

  class ExpectException : public ParserException {
  public:
    ExpectException(const std::string &input, size_t pos, const std::string &msg)
        : ParserException(input, pos), _msg() {
      strncpy(_msg, msg.c_str(), PARSER_EXCEPTION_BUF_SIZE);
    };

    const char *what() const noexcept override { return _msg; }

  private:
    char _msg[PARSER_EXCEPTION_BUF_SIZE];
  };

  class ExpectWrongTokenException : public ExpectException {
  public:
    ExpectWrongTokenException(const std::string &input, size_t pos, const std::string &msg)
        : ExpectException(input, pos, msg) {};
  };

  class ExpectMissingTokenException : public ExpectException {
  public:
    ExpectMissingTokenException(const std::string &input, const std::string &msg)
        : ExpectException(input, input.size(), msg) {};
  };

  class MissingOperandException : public ParserException {
  public:
    MissingOperandException(const std::string &input, size_t pos)
        : ParserException(input, pos) {};
  };

  class NoSuchBinaryOperatorException {
  public:
    explicit NoSuchBinaryOperatorException(token::Symbol symbol)
      : _symbol(symbol) {};

    token::Symbol get_symbol() { return _symbol; };

  private:
      token::Symbol _symbol;
  };

  class NoSuchUnaryOperatorException {
  public:
    explicit NoSuchUnaryOperatorException(token::Symbol symbol)
      : _symbol(symbol) {};

    token::Symbol get_symbol() { return _symbol; };

  private:
      token::Symbol _symbol;
  };

}

#endif //XENDBG_PARSEREXCEPTION_HPP
