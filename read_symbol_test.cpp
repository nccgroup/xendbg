#include <cassert>
#include <iostream>

#include <elfio/elfio.hpp>

int main(int argc, char **argv) {
  ELFIO::elfio reader;

  assert(reader.load(argv[1]));

  for (auto section : reader.sections) {
    if (section->get_type() == SHT_SYMTAB) {
      const ELFIO::symbol_section_accessor symbols(reader, section);
      const size_t num_symbols = symbols.get_symbols_num();
      for (size_t i = 0; i < num_symbols; ++i) {
        std::string       name;
        ELFIO::Elf64_Addr value;
        ELFIO::Elf_Xword  size;
        unsigned char     bind;
        unsigned char     type;
        ELFIO::Elf_Half   section_index;
        unsigned char     other;

        symbols.get_symbol(i, name, value, size, bind, type, section_index, other);

        if (type == STT_FUNC && value > 0)
          std::cout << name << " address: "
            << std::hex << std::showbase << value << std::endl;
      }
    }
  }
}
