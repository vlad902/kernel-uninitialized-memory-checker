// RUN: %clang_analyze_cc1 -analyzer-checker=core,alpha.security.KernelMemoryDisclosure -analyzer-store=region -verify -fno-builtin %s

#include "common.h"

void partially_initialized_string1() {
  char buf[16];
  strcpy(buf, "abc");

  copyout(buf, NULL, strlen(buf));
  copyout(&buf, NULL, strlen(buf));

  copyout(buf, NULL, sizeof(buf)); // expected-warning{{Copies out a struct with a partially unsanitized field}}
  copyout(&buf, NULL, sizeof(buf)); // expected-warning{{Copies out a struct with a partially unsanitized field}}
}

void partially_initialized_string2() {
  struct {
    char str[100];
  } s;

  strncpy(s.str, "", 99);
  copyout(&s, NULL, 100); // expected-warning{{Copies out a struct with a partially unsanitized field}}
}

// strlcpy() doesn't initialize the whole buffer
void strlcpy_initialization() {
  char foo[16];
  strlcpy(foo, "a", sizeof(foo));

  copyout(foo, NULL, strlen(foo));
  copyout(foo, NULL, sizeof(foo)); // expected-warning{{Copies out a struct with a partially unsanitized field}}
}

// strncpy() does initialize the whole string
void strncpy_initialization() {
  char foo[16];
  strncpy(foo, "a", sizeof(foo));

  copyout(foo, NULL, strlen(foo));
  copyout(foo, NULL, sizeof(foo));
}
