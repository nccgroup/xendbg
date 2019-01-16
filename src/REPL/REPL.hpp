//
// Copyright (C) 2018-2019 NCC Group
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

#ifndef XENDBG_REPL_HPP
#define XENDBG_REPL_HPP

#include <cassert>
#include <memory>
#include <optional>
#include <ostream>
#include <string>
#include <vector>

#include "Command/Action.hpp"
#include "Command/CommandBase.hpp"

namespace xd::repl {

  class REPL {
  private:
    using CommandPtr = std::unique_ptr<cmd::CommandBase>;
    using PromptConfiguratorFn = std::function<std::string()>;
    using NoMatchHandlerFn = std::function<void(const std::string &)>;
    using ActionHandlerFn = std::function<void(const cmd::Action &)>;
    using CompleterFn = std::function<std::optional<std::vector<std::string>>(const std::string &)>;

  public:
    static void run(REPL& repl, ActionHandlerFn action_handler);

  private:
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
    const std::string &get_prompt() { return _prompt; };
    void print_help(std::ostream &out);

    void set_prompt_configurator(PromptConfiguratorFn f) {
      _prompt_configurator = std::move(f);
    }
    void set_no_match_handler(NoMatchHandlerFn f) {
      _no_match_handler = std::move(f);
    }
    void set_custom_completer(CompleterFn f) {
      _custom_completer = std::move(f);
    }

  private:
    bool _running;
    std::string _prompt;
    std::vector<CommandPtr> _commands;
    PromptConfiguratorFn _prompt_configurator;
    NoMatchHandlerFn _no_match_handler;
    CompleterFn _custom_completer;

  private:
    std::vector<std::string> complete(
        const std::string &s);
    std::optional<cmd::Action> interpret_line(const std::string& line);
    std::string read_line();

    void run(ActionHandlerFn action_handler);

  };

}

#endif //XENDBG_REPL_HPP
