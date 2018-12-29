// RUN: %clang_analyze_cc1 -analyzer-checker=core,alpha.security.KernelMemoryDisclosure -analyzer-store=region -verify -fno-builtin %s

#include "common.h"

void simple() {
  struct {
    int i1;
    int i2;
  } s1, s2;

  s1.i1 = 0;
  copyout(&s1, NULL, sizeof(s1)); // expected-warning{{Copies out a struct with untouched element(s): i2}}

  // We don't warn on uninitialized fields if >50% of the fields are
  // uninitialized.
  copyout(&s2, NULL, sizeof(s2));
}

void short_copyout() {
  struct {
    int i1;
    int i2;
  } s;

  s.i1 = 0;
  copyout(&s, NULL, sizeof(int));
  // We only look for copies of the entire struct size or larger
  copyout(&s, NULL, sizeof(s) - 1);
  copyout(&s, NULL, sizeof(s)); // expected-warning{{Copies out a struct with untouched element(s): i2}}
}

void zero_length_field() {
  struct {
    int i;
    char str[0];
  } s;

  s.i = 0;
  copyout(&s, NULL, sizeof(s));
}

void memset_field() {
  struct {
    int i;
    struct {
      int a;
      char b[4];
    } j;
  } s;
  s.i = 0;
  memset(&s.j, 0, sizeof(s.j));
  memcpy(&s.j, NULL, s.i);
  copyout(&s, NULL, sizeof(s));
}
