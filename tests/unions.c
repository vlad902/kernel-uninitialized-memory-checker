// RUN: %clang_analyze_cc1 -analyzer-checker=core,alpha.security.KernelMemoryDisclosure -analyzer-store=region -verify -fno-builtin %s

#include "common.h"

void basic() {
  struct {
    union {
      char c;
      int i;
    } u;
  } s1, s2;

  s1.u.i = 0;
  copyout(&s1, NULL, sizeof(s1));

  s2.u.c = 0;
  copyout(&s2, NULL, sizeof(s2)); // expected-warning{{Copies out a struct with a union element with different sizes}}
}

void nested_struct_union() {
  struct {
    union {
      int i;
      struct { int i; } s;
    } u;
  } s1, s2;

  s1.u.i = 0;
  copyout(&s1, NULL, sizeof(s1));

  s2.u.s.i = 0;
  copyout(&s2, NULL, sizeof(s2));

  struct {
    union {
      int i;
      struct { char c; } s;
    } u;
  } s3;

  s3.u.s.c = 0;
  copyout(&s3, NULL, sizeof(s3)); // expected-warning{{Copies out a struct with a union element with different sizes}}
}
