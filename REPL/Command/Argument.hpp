//
// Created by Spencer Michaels on 8/20/18.
//

#ifndef XENDBG_ARGUMENT_HPP
#define XENDBG_ARGUMENT_HPP

#include <functional>
#include <ostream>
#include <string>

namespace xd::util {

  class IndentHelper;

}

namespace xd::repl::cmd {

  class Argument {
  public:
    using MatcherFn = std::function<std::string::const_iterator(
        std::string::const_iterator, std::string::const_iterator)>;

    Argument(std::string name, std::string description,
             MatcherFn matcher, std::string default_value = "")
        : _name(std::move(name)), _description(std::move(description)),
          _matcher(std::move(matcher)), _default_value(std::move(default_value)) {};

    void print(std::ostream& out, xd::util::IndentHelper& indent) const;

    const std::string& get_name() const { return _name; };
    const std::string& get_description() const { return _description; };
    const std::string& get_default_value() const { return _default_value; };

    virtual std::string::const_iterator match(
        std::string::const_iterator begin, std::string::const_iterator end) const {
      return _matcher(begin, end);
    };

  private:
    const std::string _name;
    const std::string _description;
    const MatcherFn _matcher;
    const std::string _default_value;
  };

}

#endif //XENDBG_ARGUMENT_HPP
