# Tentative commands list
Commands auto-complete on tab (via readline).

```
guest
 list <id>/<name>
   List Xen guests.
 attach <id>/<name> [filename]
   Attach to a guest.
 detach
   Detach from the current guest.

break
 <expr>
   Create a breakpoint.
 list
   List breakpoints (ID and addr/symbol).
 delete <id>
   Delete a breakpoint.

registers
 Prints entire register state
 Note: setting registers can be done through variables

pin
 <expr>
   Pin an expression to print at each line.
 registers
   Pin the whole register list (shortcut).
 list
   List expressions set to print at each REPL loop.
 delete <id>
   Remove expression.
?inspect <expr>
   Print the result of inspecting the memory address <expr>.
   Otherwise, prints the value of <expr>.

inspect <expr>
 -n/--num-words <expr>
   Number of words to read.
   Default 1.
 -s/--word-size <b/h/w/g>
   Word size (8/16/32/64)
   Default 64 or 32, depending on guest word size.

set <<expr1> Equals <expr>>
  where <expr1> is Dereference or Variable
```

# REPL implementation

```
class REPL {
public:
  template <typename Ts...>
  static REPL& init(Ts... args) {
    _s_instance = REPL(args...);
    rl_attempted_completion_function = completer;
  };

  static void deinit() {
    _s_instance = std::nullopt;
    rl_attempted_completion_function = nullptr;
  };

  void add_command(Command cmd);

private:
  static std::optional<REPL> _s_instance;
  static char **rl_completer(const char *text, int begin, int end);
  static char *rl_completion_generator(const char *text, int state);

private:
  REPL() = default;
  REPL(const std::vector<Command>& commands);

private:
  std::vector<Command> _commands;
}
```
