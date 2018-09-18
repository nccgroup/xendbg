//
// Created by Spencer Michaels on 8/20/18.
//

#ifndef XENDBG_FLAGSHANDLE_HPP
#define XENDBG_FLAGSHANDLE_HPP

#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "ArgsHandle.hpp"
#include "Flag.hpp"

namespace xd::repl::cmd {

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
}

#endif //XENDBG_FLAGSHANDLE_HPP
