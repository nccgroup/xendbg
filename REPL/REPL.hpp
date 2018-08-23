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
    using PromptConfiguratorFn = std::function<std::string()>;

    explicit REPL(std::string prompt = "> ");

    static std::optional<REPL> _s_instance;
    static std::vector<std::string> _s_completion_options;

    static void init_readline();
    static void deinit_readline();
    static char **attempted_completion_function(const char *text, int begin, int end);
    static char *command_generator(const char *text, int state);

  public:

    void add_command(CommandPtr cmd);
    void set_prompt_configurator(PromptConfiguratorFn f) {
      _prompt_configurator = f;
    }
    void run();

  private:
    bool _running;
    std::string _prompt;
    std::vector<CommandPtr> _commands;
    PromptConfiguratorFn _prompt_configurator;

  private:
    std::string read_line();
    void interpret_line(const std::string& line);
    void print_help();

    std::vector<std::string> complete(const std::string &s);
  };

}

#endif //XENDBG_REPL_HPP
