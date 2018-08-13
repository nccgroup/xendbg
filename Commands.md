# Tentative commands list
Commands auto-complete on tab (via readline).

```
guest
 -l/--list <id>/<name>
   List Xen guests.
 -a/--attach <id>/<name> [filename]
   Attach to a guest.
 -d/--detach
   Detach from the current guest.
 -c/--create <filename>
   Create guest, attaching automatically.
 -k/--kill
   Kill current guest.
 -r/--restart
   Restart current guest. TOOD: possible or not? Need to get path to .xl file.

break [<expr>]
   Create a breakpoint.
 -l/--list
   List breakpoints (ID and addr/symbol).
 -d/--delete <id>
   Delete a breakpoint.

registers
 Prints entire register state
 Note: setting registers can be done through variables

print [<expr>/registers]
 -l/--list
   List expressions set to print at each REPL loop.
 -d/--delete <id>
   Remove expression.
 -i/--inspect (inspect args)
   Print the result of inspecting the memory address <expr>.
   Otherwise, prints the value of <expr>.

inspect <expr>
 -n/--num-words <expr>
   Number of words to read.
 -s/--word-size <b/h/w/g>
   Word size (8/16/32/64)

set <Dereference> = <expr>
set <Variable> = <expr>
```
