// structs held as globals or arguments are considered initialized.

// RUN: %clang_analyze_cc1 -analyzer-checker=core,alpha.security.KernelMemoryDisclosure -analyzer-store=region -verify -fno-builtin %s

#include "common.h"

struct __s {
  char c;
  int i;
};

struct __s global;
void global_considered_initialized() {
  copyout(&global, NULL, sizeof(global));
}

void static_considered_initialized() {
  static struct __s _static;
  copyout(&_static, NULL, sizeof(_static));
}

void arg_considered_initialized(struct __s *arg) {
  copyout(arg, NULL, sizeof(*arg));
  copyout(&arg[1], NULL, sizeof(*arg));
}

void external_function_initializes() {
  extern void foo(struct __s *);
  struct __s s;
  foo(&s);
  // TODO this shouldn't warn
  copyout(&s, NULL, sizeof(s)); // expected-warning{{Copies out a struct with uncleared padding}}
}

static void interprocedural(struct __s *arg) {
  copyout(arg, NULL, sizeof(*arg)); // expected-warning{{Copies out a struct with uncleared padding}}
}

void arg_with_interprocedural_def_not_initialized() {
  struct __s s;
  interprocedural(&s);
}
