//
// Created by Spencer Michaels on 8/12/18.
//

#ifndef XENDBG_REPL_HPP
#define XENDBG_REPL_HPP

#include <cassert>
#include <optional>
#include <string>
#include <vector>

#include "Command/Command.hpp"

namespace xd::repl {

  class REPL {
  public:
    template <typename... Ts>
    static REPL& init(Ts... args) {
      assert(!_s_instance.has_value());
      _s_instance = REPL(args...);
      init_readline();
      return _s_instance.value();
    }

    static void deinit();

  private:
    using CommandVector = std::vector<std::unique_ptr<cmd::CommandBase>>;
    explicit REPL(std::string prompt = "> ", CommandVector commands = {});

    static std::optional<REPL> _s_instance;
    static std::vector<std::string> _s_completion_options;

    static void init_readline();
    static void deinit_readline();
    static char **attempted_completion_function(const char *text, int begin, int end);
    static char *command_generator(const char *text, int state);

  public:
    std::string read_line();
    void interpret_line(const std::string& line);
    void set_prompt(std::string prompt) { _prompt = std::move(prompt); }
    void add_command(cmd::Command cmd) { _commands.push_back(std::move(cmd)); }

  private:
    std::string _prompt;
    CommandVector _commands;

  };

}

#endif //XENDBG_REPL_HPP
