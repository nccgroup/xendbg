# Miscellaneous design notes

```
Action function signature should probably be

  void(REPL&, Debugger&)

Actions can modify either the debugger state (to attach to and modify guests)
or the REPL state itself (to quit, print help, or change the prompt)

Alternately, it would be nice if the REPL wasn't tied to the debugger at all.

```
