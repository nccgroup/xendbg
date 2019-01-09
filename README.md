# xendbg - The Xen debugger that actually works!

`xendbg` is a feature-complete reference implementation of a Xen VMI debugger,
superseding Xen's own `gdbsx`. It can debug both HVM and PV guests, and
provides both a standalone REPL and an LLDB server mode.

## Feature list

* Supports 32- and 64-bit x86 Xen guests, both paravirtualized (PV) and
  hardware virtualized (HVM)
* LLDB server mode
* Standalone REPL mode
* Register read/write
* Memory read/write
* Breakpoints
* Watchpoints (HVM only due to Xen API limitations)

## Command line options

```
-h,--help                   Print this help message and exit
-n,--non-stop-mode          Enable non-stop mode (HVM only), making step,
                              continue, breakpoints, etc. only apply to the
                              current thread.
-d,--debug                  Enable debug logging.
-s,--server PORT            Start as an LLDB stub server on the given port.
                              If omitted, xendbg will run as a standalone REPL.
-i,--ip PORT Needs: --server
                            Start the stub server on the given address.
-a,--attach DOMAIN          Attach to a single domain given either its domid
                              or name. If omitted, xendbg will start a server
                              for each domain on sequential ports starting from
                              PORT, adding and removing ports as domains start
                              up and shut down.
```

## Server mode

If run with the `--server` argument, `xendbg` will start up an LLDB server on
the specified port. If a domain is specified with `--attach`, the server will
connect to that domain immediately and close once it is destroyed. Otherwise,
it will open one port per Xen domain, starting at the given port and counting
up. The server will open and close ports as domains are created and destroyed,
and will only exit when the user explicitly sends a `CTRL-C`.

In either case, LLDB can then connect to any of `xendbg`'s ports using the
`gdb-remote` command, providing the user with a seamless and familiar debugging
experience.

![LLDB mode](demos/xendbg-lldb1.png)

![LLDB](demos/xendbg-lldb2.png)

## REPL mode

`xendbg` will start in a standalone mode if run without the `--server`
argument. This mode provides a REPL with access to all of the debugging
functions that the server mode makes available to LLDB, but without the
dependency on LLDB itself. The REPL itself, of course, is substantially
more basic than that of LLDB.

Standalone mode has contextual tab-completion for all commands. Hit `<tab>` at
any point to list completion options; if only one option is available, it will
be expanded automatically.

![REPL mode](demos/xendbg-repl.gif)

### Command list

```
breakpoint: Manage breakpoints.
  create <addr>
    Create a breakpoint.
  delete <id>
    Delete a breakpoint.
  list: List breakpoints.

continue: Continue until the next breakpoint.

cpu: Get/set the current CPU.
  get: Get the current CPU.
  set <id>
    Switch to a new CPU.

disassemble <addr> <len>
  Disassemble instructions.

examine [flags] <expr>
    Read memory.
  -w/--word-size <size>
    Size of each word to read.
  -n/--num-words <num>
    Number of words to read.

guest: Manage guest domains.
  list: List all guests and their respective states.
  attach <domid/name>
    Attach to a domain.
  detach: Detach from the current domain.
  pause: Pause the current domain.
  unpause: Unpause the current domain.

help: Print this list.

info: Query the state of Xen, the attached guest and its registers.
  guest: Query the state of the current guest.
  registers: Query the register state of the current domain.
  variables: Query variables.
  xen: Query Xen version and capabilities.

print [flags] <expr>
    Display the value of an expression.
  -f/--format <fmt>
    Format.

quit: Quit.

set [flags] <{$var, *expr} = expr>
    Write to a variable, register, or memory region.
  -w/--word-size <size>
    Size of each word to read.

step: Step forward one instruction.

symbol: Load symbols.
  list: List all symbols.
  load <file>
    Load symbols from a file.
  clear: Clear all loaded symbols.

unset <$var>
  Unset a variable.

watchpoint: Manage watchpoints.
  create <addr> <len> <type>
    Create a watchpoint.
  delete <id>
    Delete a watchpoint.
  list: List watchpoints.
```
