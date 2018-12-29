#pragma once

#define NULL (void*)0

typedef unsigned long size_t;

void *memcpy(void *restrict dst, const void *restrict src, size_t n);
void *memset(void *b, int c, size_t len);
void bzero(void *s, size_t n);

size_t strlen(const char *s);
size_t strlcpy(char * restrict dst, const char * restrict src, size_t size);
char *strcpy(char * dst, const char * src);
char *strncpy(char * dst, const char * src, size_t len);
int snprintf(char * str, unsigned int size, const char * format, ...);

void copy_to_user(char *a2, void *a1, int a3);
void copy_from_user(void *a2, void *a1, int a3);
void copyout(void *a1, char *a2, int a3);
void copyin(void *a1, void *a2, int a3);
