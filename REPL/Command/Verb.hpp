//
// Created by Spencer Michaels on 8/19/18.
//

#ifndef XENDBG_VERB_HPP
#define XENDBG_VERB_HPP

#include <optional>
#include <map>
#include <string>
#include <variant>

#include "Action.hpp"

namespace xd::repl::cmd {

  class Argument {
  public:
    Argument(std::string name, std::string description)
      : _name(name), _description(description) {};

    virtual std::string::const_iterator match(
        std::string::const_iterator begin, std::string::const_iterator end) const;

  private:
    std::string _name;
    std::string _description;
  };

  class Flag {
  public:
    Flag(char short_name, std::string long_name, std::string description,
        std::vector<Argument> args)
      : _short_name(short_name), _long_name(long_name), _description(description),
        _args(std::move(args)) {};

    std::string::const_iterator match(
        std::string::const_iterator begin, std::string::const_iterator end) const;

  private:
    char _short_name;
    std::string _long_name;
    std::string _description;
    std::vector<Argument> _args;
  };

  class Verb {
  private:
    class ArgsHandle {
    private:
      using ArgsList = std::vector<std::pair<std::string, std::string>>;

    public:
      ArgsHandle() {};
      ArgsHandle(ArgsList args) : _args(std::move(args)) {};

      // TODO: no OOB error handling
      template <typename T, typename F>
      T get(size_t index, F f) const {
        auto s = _args.at(index).first;
        return f(s);
      }

    private:
      ArgsList _args;
    };

    class FlagsHandle {
    private:
      using FlagHandle = std::optional<ArgsHandle>;
      using FlagsList = std::vector<std::pair<std::pair<char, std::string>, ArgsHandle>>;

    private:
      template <typename F>
      FlagHandle get_predicate(F pred) const {
        auto found = std::find_if(_flags.begin(), _flags.end(), pred);

        if (found == _flags.end())
          return std::nullopt;

        return found->second;
      }

    public:
      FlagsHandle(FlagsList flags) : _flags(std::move(flags)) {};

      bool has(char short_name) const {
        return get(short_name).has_value();
      }
      bool has(std::string long_name) const {
        return get(long_name).has_value();
      }

      FlagHandle get(char short_name) const {
        return get_predicate([short_name](const auto& f) {
          return f.first.first == short_name;
        });
      }

      FlagHandle get(std::string long_name) const {
        return get_predicate([long_name](const auto& f) {
          return f.first.second == long_name;
        });
      }

    private:
      FlagsList _flags;
    };

  public:
    Verb(std::string name, std::string description,
        std::vector<Flag> flags, std::vector<Argument> args)
      : _name(std::move(name)), _description(std::move(description)),
        _flags(flags), _args(args) {};

    std::string get_name() const { return _name; };

    std::optional<Action> match(std::string::const_iterator begin,
        std::string::const_iterator end) const; /*{
      auto [flags, end_flags] = match_flags(begin, end);
      auto [args, end_args] = match_args(end_flags, end);
    };*/

  private:
    std::pair<int, std::string::const_iterator> match_flags(
        std::string::const_iterator begin, std::string::const_iterator end) const;
    std::pair<int, std::string::const_iterator> match_args(
        std::string::const_iterator begin, std::string::const_iterator end) const;

  private:
    const std::string _name;
    const std::string _description;
    std::vector<Flag> _flags;
    std::vector<Argument> _args;
  };

}

#endif //XENDBG_VERB_HPP
