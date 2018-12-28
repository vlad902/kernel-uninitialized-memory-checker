// RUN: %clang_analyze_cc1 -analyzer-checker=core,alpha.security.KernelMemoryDisclosure -analyzer-store=region -verify -fno-builtin %s

#include "common.h"

struct padded_struct {
  char c;
  int i;
};

// TODO: Test an XNU interface included in MachInterface.h

void copyout_functions() {
  struct padded_struct foo;

  // FreeBSD
  copyout(&foo, NULL, sizeof(foo)); // expected-warning{{Copies out a struct with uncleared padding}}

  // Linux
  copy_to_user(NULL, &foo, sizeof(foo)); // expected-warning{{Copies out a struct with uncleared padding}}
}

void struct_initialization_functions() {
  struct padded_struct foo1;
  bzero(&foo1, sizeof(foo1));
  copyout(&foo1, NULL, sizeof(foo1));

  struct padded_struct foo2;
  memset(&foo2, 0, sizeof(foo2));
  copyout(&foo2, NULL, sizeof(foo2));

  struct padded_struct foo3;
  memcpy(&foo3, NULL, sizeof(foo3));
  copyout(&foo3, NULL, sizeof(foo3));

  struct padded_struct foo4;
  __builtin_memset(&foo4, 0, sizeof(foo4));
  copyout(&foo4, NULL, sizeof(foo4));

  struct padded_struct foo5;
  __builtin_memcpy(&foo5, NULL, sizeof(foo5));
  copyout(&foo5, NULL, sizeof(foo5));

  // FreeBSD
  struct padded_struct foo6;
  copyin(NULL, &foo4, sizeof(foo4));
  copyout(&foo4, NULL, sizeof(foo4));

  // Linux
  struct padded_struct foo7;
  copy_from_user(&foo5, NULL, sizeof(foo5));
  copy_to_user(NULL, &foo5, sizeof(foo5));
}

void memcpy_by_reference() {
  struct { char c[4]; } s;
  void *ptr = &s;

  memcpy(ptr, "abcd", 4);
  copyout(&s, NULL, sizeof(s));
}

void freebsd_malloc() {
  void *malloc(size_t, int, int) __attribute__((__malloc__));
  const int M_DEVBUF = 1;
  const int M_WAITOK = 2;
  const int M_ZERO = 0x100;

  struct padded_struct *foo1 = malloc(sizeof(struct padded_struct), M_DEVBUF, M_WAITOK);
  foo1->c = foo1->i = 0;
  copyout(foo1, NULL, sizeof(*foo1)); // expected-warning{{Copies out a struct with uncleared padding}}

  struct padded_struct *foo2 = malloc(sizeof(struct padded_struct), M_DEVBUF, M_WAITOK | M_ZERO);
  copyout(foo2, NULL, sizeof(*foo2));
}

void xnu_malloc() {
  extern void __MALLOC(size_t, size_t, size_t, void *);
  const int M_ZERO = 0x04;

  struct padded_struct *foo1;
  __MALLOC(sizeof(struct padded_struct), 0, 0, &foo1);
  foo1->c = foo1->i = 0;
  copyout(foo1, NULL, sizeof(*foo1)); // expected-warning{{Copies out a struct with uncleared padding}}

  struct padded_struct *foo2;
  __MALLOC(sizeof(struct padded_struct), 0, M_ZERO, &foo2);
  copyout(foo2, NULL, sizeof(*foo2));
}

void linux_malloc() {
  extern void *kmalloc(size_t, int);
  extern void *kzalloc(size_t, int);

  const int GFP_ZERO = 0x8000;

  struct padded_struct *foo1 = kmalloc(sizeof(struct padded_struct), 0);
  foo1->c = foo1->i = 0;
  copyout(foo1, NULL, sizeof(*foo1)); // expected-warning{{Copies out a struct with uncleared padding}}

  struct padded_struct *foo2 = kmalloc(sizeof(struct padded_struct), GFP_ZERO);
  copyout(foo2, NULL, sizeof(*foo2));

  struct padded_struct *foo3 = kzalloc(sizeof(struct padded_struct), 0);
  copyout(foo3, NULL, sizeof(*foo3));
}
