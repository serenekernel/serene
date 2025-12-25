#pragma once
#include <stdarg.h>
#include <stddef.h>
void term_init(void);

int snvprintf(char* buffer, size_t bufsz, const char* fmt, va_list val);
int snprintf(char* buffer, size_t bufsz, const char* fmt, ...);
int vprintf(const char* fmt, va_list val);
int printf(const char* fmt, ...);
