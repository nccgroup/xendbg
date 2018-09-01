//
// Created by Spencer Michaels on 8/12/18.
//

#ifndef XENDBG_REPL_HPP
#define XENDBG_REPL_HPP

#include <cassert>
#include <memory>
#include <optional>
#include <ostream>
#include <string>
#include <vector>

#include "Command/CommandBase.hpp"

namespace xd::repl {

  class REPL {
  public:
    static void run(REPL& repl);

  private:
    using CommandPtr = std::unique_ptr<cmd::CommandBase>;
    using PromptConfiguratorFn = std::function<std::string()>;
    using NoMatchHandlerFn = std::function<void(const std::string &)>;

    static REPL *_s_instance;

    static std::vector<std::string> _s_completion_options;

    static void init_readline();
    static void deinit_readline();

    static char **attempted_completion_function(
        const char *text, int begin, int end);
    static char *command_generator(
        const char *text, int state);

  public:
    REPL();
    REPL(const REPL& other) = delete;
    REPL& operator=(const REPL& other) = delete;

    void add_command(CommandPtr cmd);
    void exit();
    void print_help(std::ostream &out);
    void set_prompt_configurator(PromptConfiguratorFn f) {
      _prompt_configurator = std::move(f);
    }
    void set_no_match_handler(NoMatchHandlerFn f) {
      _no_match_handler = std::move(f);
    }

  private:
    bool _running;
    std::string _prompt;
    std::vector<CommandPtr> _commands;
    PromptConfiguratorFn _prompt_configurator;
    NoMatchHandlerFn _no_match_handler;

  private:
    std::vector<std::string> complete(
        const std::string &s);
    void interpret_line(const std::string& line);
    std::string read_line();
    void run();

  };

}

#endif //XENDBG_REPL_HPP
