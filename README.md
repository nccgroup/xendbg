# xendbg - The Xen debugger that actually works!

`xendbg` is a feature-complete reference implementation of a Xen VMI debugger,
superseding Xen's own `gdbsx`. It can debug both HVM and PV guests, and
provides both a standalone REPL and an LLDB server mode.

## Features

* Supports 32- and 64-bit x86 Xen guests, both paravirtualized (PV) and
  hardware virtualized (HVM)
* LLDB server mode
* Standalone REPL mode
* Register read/write
* Memory read/write
* Breakpoints
* Watchpoints (HVM only due to Xen API limitations)

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

If run without the `--server` argument, `xendbg` will start as a standalone
REPL. This provides access to all of the debugging functions that the server
mode makes available to LLDB, but without the dependency on LLDB itself.
`xendbg`'s REPL, while necessarily simpler than that of LLDB, does possess
some of the same major features, including tab completion, expressions, and
variables.

Type `help` at the REPL for a full list of commands.

### Features

* **Contextual tab completion:** Hit `<tab>` at any point to list completion
  options; if only one option is available, it will be expanded automatically.
* **Expressions:** Any statements that take numerical values can also take
  expressions, e.g. `disassemble $rip+0x10 0x20`. Besides addition,
  subtraction, multiplication, division, and parenthesization, expressions also
  support:
  * The C-style dereference operator `*`, which will interpret its operand as
    an address in guest memory and read either a 32- or 64-bit value from that
    location, depending on the bitness of the guest.
  * Symbol resolution via the `&` operator.
* **Symbols:** Symbols can be loaded via `symbol load <filename>`, and
  thereafter any valid symbol name prefixed with `&` will evaluate to the
  address of that symbol and can be used in an expression, e.g. `print
  &rumprun_main1`
* **Variables:** Any C-style variable name prefaced with a dollar sign `$` is
  treated as a variable. Variables can be set with `set $my_var = {expression}`
  and unset with `unset $my_var`. In addition, when attached to a guest, its
  registers will be given variable semantics, so they can be read/written
  directly via the `set`/`print` commands, e.g. `set $rax = $rbx + 0x1337`.
  
![REPL mode](demos/xendbg-repl.gif)

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

## Build steps

The following steps were run on a vanilla Ubuntu 18.04.1 LTS.

```
sudo apt install git cmake build-essential
git submodule update --init

# Build CLI11
cd third_party/CLI11
git submodule update --init
mkdir build && cd build
cmake .. && make && sudo make install

# Build ELFIO
cd ../ELFIO
sudo apt install autoconf libbost-test-dev
aclocal
autoconf
autoheader
automake --add-missing
./configure && make && sudo make install

# Build uvw
cd ../uvw/build
sudo apt install libuv-dev
cmake .. && make && sudo make install

# Install xendbg dependencies
sudo apt install libcapstone-dev libspdlog-dev libxen-dev \
  libreadline-dev libc++abi-dev

# Build with clang. Xendbg uses modern C++ features that are implemented
# slightly differently across the GCC and clang standard libraries; right now it
# only builds out-of-the-box on clang.
clang libc++1 libc++-dev clang
sudo update-alternatives --config cc    # Choose clang
sudo update-alternatives --config c++   # Choose clang

mkdir build && cd build
cmake ..
make

# Set the default compiler back to GCC if desired
sudo update-alternatives --config cc
sudo update-alternatives --config c++
```
