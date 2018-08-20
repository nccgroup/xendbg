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

# Command structure

```
command verb [flags...] [args...]
    where flags are of the form -f or --flag
    and args are arbitrary space-separated char sequences
```

## Tentative implementation
```c++
class Command {
public:
  get_name(); { return name; }

private:
  String name;
  vector<Verb> verbs;
}

struct Verb {
  String name;
  vector<Flag> flags;
  vector<Argument> args;
}

template <typename... Args_t>
struct Flag {
  String shortName;
  String longName;
}

template <typename TopLevelExpression_t>
struct Argument {
}


auto break = Command("break");
break.add_verb(Verb<>("list"));

auto del = Verb(
  "delete",
  "Delete a breakpoint.",
  [](auto& flags, auto& args) {
    int id = args.get<int>("id");
    bool force = flags.has("force");
    std::optional<int> val = flags.get<int>("value");
    if (val) {
      // do something with val...
    }

    return [force, val, id](auto& dbg) {
      if (force)
        dbg.breakpoints.delete(id);
      if (val)
        print(val);
    };
  });

// Args are always required
del.add_arg<int>("id", "The ID of the breakpoint to delete.")
// Flags are always optional
del.add_flag<>("f", "force", "Force deletion of the breakpoint."); 
del.add_flag<int>("v", "value", "An optional value to use.", 1337); // default value
break.add_verb(del);

Verb v("do_thing");
v.add_flag(Flag<>("f", "flag"));
// or Flag<>("flag") --> automatically determines -f argument

auto input = get_input();
for (cmd : _commands) {
  auto action = cmd.match(input.begin(), input.end());
  if (action)
    action(debugger_context);
}
```
