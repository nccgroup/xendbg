//
// Created by Spencer Michaels on 8/12/18.
//

#include <iostream>
#include <string>

#include <readline/readline.h>

#include "REPL.hpp"

using xd::repl::REPL;

std::optional<REPL> REPL::_s_instance;
std::vector<std::string> REPL::_s_completion_options;

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

  /*
   * This function is only callable through a REPL instance, so we can safely
   * assume that _s_instance contains a value.
   *
   * Because there are subcommands to complete, completion options depend on
   * the *entire* line (rl_line_buffer) rather than just the last word (text).
   */
  _s_completion_options = _s_instance.value().complete(rl_line_buffer);

  return rl_completion_matches(text, REPL::command_generator);
}

char *REPL::command_generator(const char *text, int state) {
  static size_t s_index, s_text_len;
  
  if (!state) {
    s_index = 0;
    s_text_len = strlen(text);
  }

  while (s_index < _s_completion_options.size()) {
    const auto &s = _s_completion_options.at(s_index++);
    if (strncmp(text, s.c_str(), s_text_len) == 0) {
      return strdup(s.c_str());
    }
  }

  return nullptr;
}

REPL::REPL(std::string prompt)
  : _prompt(std::move(prompt))
{
}

std::string REPL::read_line() {
  return readline(_prompt.c_str());
}

void REPL::interpret_line(const std::string& line) {
  for (const auto &cmd : _commands) {
    auto action = cmd->match(line);
    if (action) {
      (action.value())();
      return;
    }
  }

  std::cerr << "Invalid input." << std::endl;
}

std::vector<std::string> REPL::complete(const std::string &s) {
  for (const auto &cmd : _commands) {
    auto options = cmd->complete(s);
    if (!options.empty())
      return options;
  }

  std::vector<std::string> options;
  std::transform(_commands.begin(), _commands.end(), std::back_inserter(options),
    [](const auto& cmd) {
      return cmd->get_name();
    });
  return options;
}
