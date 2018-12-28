// RUN: %clang_analyze_cc1 -analyzer-checker=core,alpha.security.KernelMemoryDisclosure -analyzer-store=region -verify -fno-builtin %s

#include "common.h"

struct padded_struct {
  char c;
  int i;
};

void uninitialized_padding1() {
  struct padded_struct foo;
  foo.c = foo.i = 0;

  // FreeBSD
  copyout(&foo, NULL, sizeof(foo)); // expected-warning{{Copies out a struct with uncleared padding}}

  // Linux
  copy_to_user(NULL, &foo, sizeof(foo)); // expected-warning{{Copies out a struct with uncleared padding}}
}

void uninitialized_padding2() {
  struct __foo {
    struct { char c; } s;
    int i;
  } foo;

  strncpy(&foo.s.c, "a", 1);
  foo.i = 0;
  copyout(&foo, NULL, sizeof(foo)); // expected-warning{{Copies out a struct with uncleared padding}}
}

// BROKEN ????
#if 0
void uninitialized_padding3() {
  struct __foo {
    struct { char c; short s; } s;
    int i;
  } foo;

  foo.s.c = foo.s.s = foo.i = 0;
  copyout(&foo, NULL, sizeof(foo)); // expected-warning{{Copies out a struct with uncleared padding}}
}
#endif

void no_padding() {
  struct __foo {
    int i1, i2;
  } foo;

  foo.i1 = foo.i2 = 0;
  copyout(&foo, NULL, sizeof(foo));
}

void initialized_struct() {
  struct padded_struct foo1 = {};
  copyout(&foo1, NULL, sizeof(foo1));

  struct padded_struct foo2[2] = { { .c = 0, .i = 1 }, { .c = 2, .i = 3 } };
  copyout(&foo2, NULL, sizeof(foo2));

  struct padded_struct foo3;
  foo3 = foo1;
  copyout(&foo3, NULL, sizeof(foo3));
}

void packed_struct() {
  struct __attribute__((__packed__)) packed_struct {
    char c;
    int i;
  } packed;
  packed.c = packed.i = 0;
  copy_to_user(NULL, &packed, sizeof(packed));

  struct __attribute__((__packed__)) nested_and_packed_struct {
    struct packed_struct p1, p2;
  } nested_and_packed;
  nested_and_packed.p1.c = nested_and_packed.p1.i = 0;
  nested_and_packed.p2.c = nested_and_packed.p2.i = 0;
  copy_to_user(NULL, &nested_and_packed, sizeof(nested_and_packed));
}
