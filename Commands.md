# Tentative commands list
Commands auto-complete on tab (via readline).

```
guest
 list
   List Xen domains.
 attach <domid/name>
   Attach to a domain.
 detach
   Detach from the current domain.

break
 <expr>
   Create a breakpoint.
 list
   List breakpoints (ID and addr/symbol).
 delete <id>
   Delete a breakpoint.

info
  domain
    Prints detailed info for the current domain
  registers
    Prints entire register state
  xen
    Prints Xen version and capabilities.

display
 add <expr>
   Pin an expression to print at each line.
 registers
   Pin the whole register list (shortcut).
 list
   List expressions set to print at each REPL loop.
 delete <id>
   Remove expression.
?examine <expr>
   Print the result of inspecting the memory address <expr>.
   Otherwise, prints the value of <expr>.

examine <expr>
 -n/--num-words <expr>
   Number of words to read.
   Default 1.
 -s/--word-size <b/h/w/g>
   Word size (8/16/32/64)
   Default 64 or 32, depending on domain word size.

set <<Dereference OR Variable> Equals <expr>>
  where <expr1> is Dereference or Variable
```

# Minor improvements to autocomplete

- Label completion: If you hit tab and first char of the last word is '&',
complete from the list of labels. Same with '$' and variables.
- Allow args to have autocompletion functions
  - This way, I can specify a custom completer for domain names in "guest
  attach <name>"
  - In order to do this, I need to figure out what arg is next.  I can do a
   partial match of the command string and see what arg is missing, if any.

Create Flag::match(begin, end), which matches against flag args. In Verb::match,
if none can be matched for any flags, just match flag names.


```

std::optional<Argument> xd::repl::cmd::get_next_arg(
    StrConstIt begin, StrConstIt end, const std::vector<Argument> &args)
{
  auto it = begin;
  for (const auto& arg : args) {
    it = skip_whitespace(it, end);

    auto arg_end = arg.match(it, end);
    if (arg_end == it)
      return arg;

    it = arg_end;
  }

  return std::nullopt;
}
```
