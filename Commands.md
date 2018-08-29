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

print <expr>

```
