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

# Completion implementation

```

class Command {
public:
  StrVec complete(StrConstIt begin, StrConstIt end) {
    auto next = expect(_name, begin, end);

    if (next == begin)
      return {};

    for (const auto& verb : _verbs) {
      auto vc = verb.complete;
      if (!vc.empty()) {
        return vc;
      }
    }
  };
}
```
