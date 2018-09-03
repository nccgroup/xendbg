//
// Created by Spencer Michaels on 8/20/18.
//

#ifndef XENDBG_FLAG_HPP
#define XENDBG_FLAG_HPP

#include <optional>
#include <string>
#include <vector>

#include "Argument.hpp"
#include "ArgsHandle.hpp"

namespace xd::util {

  class IndentHelper;

}

namespace xd::repl::cmd {

  class FlagNameException : public std::runtime_error {
  public:
    FlagNameException(const std::string &msg)
      : std::runtime_error(msg) {};
  };

  class Flag {
  public:
    Flag(char short_name, std::string long_name, std::string description,
        std::vector<Argument> args);

    void print(std::ostream& out, xd::util::IndentHelper& indent) const;

    void add_arg(Argument arg);

    char get_short_name() const { return _short_name; };
    const std::string& get_long_name() const { return _long_name; };
    const std::string& get_description() const { return _description; };

    std::string::const_iterator match_name(
        std::string::const_iterator begin, std::string::const_iterator end) const;
    std::pair<std::string::const_iterator, ArgsHandle> match(
        std::string::const_iterator begin, std::string::const_iterator end) const;
    std::optional<std::pair<std::string::const_iterator, Argument>> get_next_arg(
        std::string::const_iterator begin, std::string::const_iterator end) const;

  private:
    const char _short_name;
    const std::string _long_name;
    const std::string _description;
    std::vector<Argument> _args;
  };


  class FlagArgMatchFailedException : public std::exception {
  public:
    FlagArgMatchFailedException(std::string::const_iterator pos,
        Flag flag, Argument arg)
      : _pos(pos), _flag(flag), _arg(arg) {};

    std::string::const_iterator get_pos() const { return _pos; }
    const Flag &get_flag() const { return _flag; };
    const Argument &get_argument() const { return _arg; };
    
  private:
    std::string::const_iterator _pos;
    Flag _flag;
    Argument _arg;
  };

}

#endif //XENDBG_FLAG_HPP
