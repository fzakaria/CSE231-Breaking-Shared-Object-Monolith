#pragma once

#include <string>

class IPrinter {
 public:
  virtual ~IPrinter() {}
  virtual void print(std::string val) const = 0;
};

class StandardOutPrinter : public IPrinter {
 public:
  virtual void print(std::string val) const;
};

void hello_world(const IPrinter& printer);
