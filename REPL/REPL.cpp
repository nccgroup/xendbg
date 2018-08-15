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

char *completion_options[] = {
    "helloworld",
    "test",
    "thisisatest",
    "stillatest",
    NULL
};

void repl::set_prompt(const std::string &prompt) {
  _prompt = prompt;
}

void repl::start() {
  if (!_needs_init) {
    init_repl();
    _needs_init = false;
  }

  bool should_quit = false;
  while (!should_quit) {
    auto input = get_input(_prompt);
    std::cout << input << std::endl;
    should_quit = (input == "quit");
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

char *completion_generator(const char *text, int state) {
  static int list_index, len;
  char *result;

  if (!state) {
    list_index = 0;
    len = strlen(text);
  }

  while ((result = completion_options[list_index++])) {
    if (strncmp(result, text, len) == 0) {
      return strdup(result);
    }
  }

  return NULL;
}
