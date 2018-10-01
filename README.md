# xendbg - The Xen debugger that actually works

## Feature list
- [x] Debugging
  - [x] Core
    - [x] Attach to Xen domain
    - [x] Registers
      - [x] Read
      - [x] Write
    - [x] Memory
      - [x] Read
      - [x] Write
  - [x] Advanced
      - [x] Breakpoints
        - [x] Set/unset
        - [x] Check if hit
        - [x] Reset after continuin
- [x] Interface (REPL)
  - [x] Autocomplete
  - [x] Command tree
    - [x] Basic commands
    - [x] Flags/arguments
  - [x] Variables
    - [x] User-defined vars
    - [x] Registers as vars
  - [x] Expressions
    - [x] Parsing (incl. variables, memory access, symbols, etc.)
    - [x] Evaluation

## Final feature set
- [x] PV support
- [ ] HVM support
  - [ ] Registers
  - [ ] Breakpoints
  - [ ] Extra: memory watchpoints?
- [ ] Sub-registers? (rax -> eax -> ax...)
- [ ] REPL (redo with CLI11)
