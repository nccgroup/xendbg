//
// Created by Spencer Michaels on 8/12/18.
//

#ifndef XENDBG_REPL_HPP
#define XENDBG_REPL_HPP

#include <cassert>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "Command/CommandBase.hpp"

namespace xd::repl {

  class REPL {
  public:
    static REPL& init(std::string prompt) {
      assert(!_s_instance.has_value());
      _s_instance.emplace(REPL{prompt});
      init_readline();
      return _s_instance.value();
    }

    static void deinit();

  private:
    using CommandPtr = std::unique_ptr<cmd::CommandBase>;
    explicit REPL(std::string prompt = "> ");

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
    void add_command(CommandPtr cmd) { _commands.push_back(std::move(cmd)); }
    void print_help();

  private:
    std::string _prompt;
    std::vector<CommandPtr> _commands;

    std::vector<std::string> complete(const std::string &s);
  };

}

#endif //XENDBG_REPL_HPP
