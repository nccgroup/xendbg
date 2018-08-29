# Tentative commands list
Commands auto-complete on tab (via readline).

```
guest
 list
   List Xen guests.
 attach <domid/name>
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

info
  domain
    Prints detailed info for the current domain
  registers
    Prints entire register state
  xen
    Prints Xen version and capabilities.

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

set <<Dereference OR Variable> Equals <expr>>
  where <expr1> is Dereference or Variable
```

# Debugger (top-level application) implementation

```
class Debugger {
public:
    void attach(DomID domid);
    void detach();

    void set_variable(std::string name, Value value) {
      if (is_register32_name(name)) {
        _domain.set_register(/*name -> enum*/, value);
      } else if (is_register64_name(name)) {
        _domain.set_register(/*name -> enum*/, value);
      }

      if (_variables.count(name) < 1)
        _variables[name] = Variable(name, value);
    }

private:
    std::shared_ptr<XenHandle> _xen;
    std::optional<Domain> _domain;
}
```
