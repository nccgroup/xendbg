#include "CommandLine.hpp"

using xd::CommandLine;

int main(int argc, char **argv) {
  return CommandLine().parse(argc, argv);
}
