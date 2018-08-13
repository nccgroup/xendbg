# xendbg - The Xen debugger that actually works

## Feature list
- [ ] Debugging
  - [ ] Core
    - [x] Attach to Xen domain
    - [ ] Registers
      - [x] Read
      - [ ] Write
    - [ ] Memory
      - [ ] Read
      - [ ] Write
  - [ ] Advanced
      - [ ] Breakpoints
        - [ ] Set/unset
        - [ ] Check if hit
- [ ] Interface (REPL)
  - [ ] Command tree
    - [ ] Basic commands
    - [ ] Flags/arguments
  - [ ] Variables
    - [ ] User-defined vars
    - [ ] Registers as auto-generated vars
  - [ ] Expressions
    - [x] Parsing (incl. variables, memory access, symbols, etc.)
    - [ ] Evaluation
