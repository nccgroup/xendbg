# xendbg - The Xen debugger that actually works

## Feature list
- [ ] Debugging
  - [x] Core
    - [x] Attach to Xen domain
    - [x] Registers
      - [x] Read
      - [x] Write
    - [x] Memory
      - [x] Read
      - [x] Write
  - [ ] Advanced
      - [ ] Breakpoints
        - [ ] Set/unset
        - [ ] Check if hit
        - [ ] Reset after continuin
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
