//
// Created by Spencer Michaels on 8/12/18.
//

#ifndef XENDBG_PARSEREXCEPTION_HPP
#define XENDBG_PARSEREXCEPTION_HPP

#include <cstring>
#include <stdexcept>
#include <string>

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

}

#endif //XENDBG_PARSEREXCEPTION_HPP
