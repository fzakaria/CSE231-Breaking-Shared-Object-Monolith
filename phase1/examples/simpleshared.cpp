#include "simpleshared.h"

#include <iostream>

void hello_world(const IPrinter& printer) { printer.print("hello world"); }

void StandardOutPrinter::print(std::string val) const {
  std::cout << val << std::endl;
}
