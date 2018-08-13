//
// Created by Spencer Michaels on 8/12/18.
//

#include <iostream>
#include <string>

#include <readline/readline.h>

#include "REPL.hpp"

static std::string _prompt;
static bool _needs_init = true;

std::string get_input(const std::string& prompt);
void init_repl();
char **completer(const char *text, int begin, int end);
char *completion_generator(const char *text, int status);

void repl::set_prompt(const std::string &prompt) {
  _prompt = prompt;
}

void repl::do_repl() {
  if (!_needs_init) {
    init_repl();
    _needs_init = false;
  }

  bool has_quit = false;
  while (!has_quit) {
    auto input = get_input(_prompt);
    std::cout << input << std::endl;
    has_quit = (input == "quit");
  }
}

void init_repl() {
  rl_attempted_completion_function = completer;
  _needs_init = true;
}

std::string get_input(const std::string& prompt) {
  const char* input = readline(prompt.c_str());
  return std::string(input);
}

char **completer(const char *text, int begin, int end) {
  rl_attempted_completion_over = 1;
  return rl_completion_matches(text, completion_generator);
}

char *completion_generator(const char *text, int status) {
  return NULL;
}
