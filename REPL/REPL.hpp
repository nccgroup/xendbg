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
    static REPL& init();
    static void deinit();

  private:
    using CommandPtr = std::unique_ptr<cmd::CommandBase>;
    using PromptConfiguratorFn = std::function<std::string()>;

    REPL();
    REPL(const REPL& other) = delete;
    REPL& operator=(REPL& other) = delete;

    static std::optional<REPL> _s_instance;
    static std::vector<std::string> _s_completion_options;

    static void init_readline();
    static void deinit_readline();
    static char **attempted_completion_function(const char *text, int begin, int end);
    static char *command_generator(const char *text, int state);

  public:

    void add_command(CommandPtr cmd);
    void exit();
    void run();
    void set_prompt_configurator(PromptConfiguratorFn f) {
      _prompt_configurator = f;
    }

  private:
    bool _running;
    std::string _prompt;
    std::vector<CommandPtr> _commands;
    PromptConfiguratorFn _prompt_configurator;

  private:
    void add_default_commands();
    std::vector<std::string> complete(const std::string &s);
    void interpret_line(const std::string& line);
    void print_help();
    std::string read_line();

  };

}

#endif //XENDBG_REPL_HPP
