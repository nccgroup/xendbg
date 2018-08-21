//
// Created by Spencer Michaels on 8/19/18.
//

#ifndef XENDBG_VERB_HPP
#define XENDBG_VERB_HPP

#include <optional>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include "Action.hpp"
#include "Argument.hpp"
#include "Flag.hpp"

namespace xd::repl::cmd {

  class Verb {
  private:
    class ArgsHandle {
    private:
      using ArgsList = std::vector<std::pair<std::string, std::string>>;

    public:
      static std::pair<ArgsHandle, std::string::const_iterator> match_args(
          std::string::const_iterator begin, std::string::const_iterator end,
          const std::vector<cmd::Argument> &args)
      {
        ArgsHandle args_handle;

        auto it = begin;
        for (const auto& arg : args) {
          it = skip_whitespace(it, end);

          auto arg_end = arg.match(it, end);
          if (arg_end == it)
            throw std::runtime_error("Missing argument '" + arg.get_name() + "'!");

          args_handle.put(arg.get_name(), std::string(it, arg_end));
          it = arg_end;
        }

        return std::make_pair(args_handle, it);
      }

      void put(std::string name, std::string value) {
        _args.push_back(std::make_pair(std::move(name), std::move(value)));
      }

      // TODO: no OOB error handling
      template <typename T, typename F>
      T get(size_t index, F convert) const {
        if (index >= _args.size())
          throw std::runtime_error("No such argument!");

        auto value = _args.at(index).second;
        return convert(value);
      }

      template <typename T, typename F>
      T get(const std::string& name, F convert) const {
        auto found = std::find_if(_args.begin(), _args.end(),
          [name](const auto& p) {
            return p.first == name;
          });

        if (found == _args.end())
          throw std::runtime_error("No such argument!");

        return convert(found->second);
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
      void put(const Flag& flag, ArgsHandle args) {
        auto flag_names = std::make_pair(flag.get_short_name(), flag.get_long_name());
        _flags.push_back(std::make_pair(flag_names, args));
      }

      bool has(char short_name) const {
        return get(short_name).has_value();
      }
      bool has(const std::string& long_name) const {
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

    using MakeActionFn = std::function<Action(const FlagsHandle&, const ArgsHandle&)>;

  public:
    Verb(std::string name, std::string description,
        std::vector<Flag> flags, std::vector<Argument> args, MakeActionFn make_action)
      : _name(std::move(name)), _description(std::move(description)),
        _flags(std::move(flags)), _args(std::move(args)), _make_action(make_action) {};

    std::string get_name() const { return _name; };

    std::optional<Action> match(std::string::const_iterator begin,
        std::string::const_iterator end) const;

  private:
    std::pair<FlagsHandle, std::string::const_iterator> match_flags(
        std::string::const_iterator begin, std::string::const_iterator end) const;
    std::pair<ArgsHandle, std::string::const_iterator> match_args(
        std::string::const_iterator begin, std::string::const_iterator end) const;

    std::pair<ArgsHandle, std::string::const_iterator> match_args(
        std::string::const_iterator begin, std::string::const_iterator end,
        const std::vector<Argument>& args) const;

  private:
    const std::string _name;
    const std::string _description;
    std::vector<Flag> _flags;
    std::vector<Argument> _args;
    MakeActionFn _make_action;
  };

}

#endif //XENDBG_VERB_HPP
