//
// Created by Spencer Michaels on 8/12/18.
//

#include <iostream>
#include <string>

#include <readline/readline.h>

#include "REPL.hpp"

using xd::repl::REPL;

std::optional<REPL> REPL::_s_instance;
std::vector<std::string>REPL:: _s_completion_options;

void REPL::deinit() {
  assert(_s_instance.has_value());
  _s_instance = std::nullopt;
  deinit_readline();
}

void REPL::init_readline() {
  rl_attempted_completion_function = REPL::attempted_completion_function;
}

void REPL::deinit_readline() {
  rl_attempted_completion_function = nullptr;
}

char **REPL::attempted_completion_function(const char *text, int begin, int end) {
  rl_attempted_completion_over = 1;

  return rl_completion_matches(text + begin, REPL::command_generator);
}

char *REPL::command_generator(const char *text, int state) {
  static int index, text_len;

  if (!state) {
    index = 0;
    text_len = strlen(text);
  }

  for (const auto& s : _s_completion_options) {
    if (strncmp(text, s.c_str(), text_len) == 0) {
      return strdup(s.c_str());
    }
  }

  return NULL;
}

REPL::REPL(std::string prompt, std::vector<cmd::Command> commands)
  : _prompt(prompt), _commands(std::move(commands))
{
}

std::string REPL::read_line() {
  return readline(_prompt.c_str());
}

void REPL::interpret_line(const std::string& line) {
  for (const auto &cmd : _commands) {
    auto action_opt = cmd.match(line);
    if (action_opt) {
      auto action = action_opt.value();
      action();
      return;
    }
  }

  std::cerr << "Invalid input." << std::endl;
}
