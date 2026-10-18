#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define KSTUFF_PATCH_MAX 8

struct kstuff_patch {
  uintptr_t address;
  size_t length;
  uint8_t original[KSTUFF_PATCH_MAX];
  uint8_t replacement[KSTUFF_PATCH_MAX];
  int installed;
};

void kstuff_log(const char *format, ...) __attribute__((format(printf, 1, 2)));

pid_t kstuff_find_pid(const char *name);

int kstuff_patch_prepare(pid_t pid, kstuff_patch *patch);
int kstuff_patch_commit(pid_t pid, kstuff_patch *patch);
int kstuff_patch_restore(pid_t pid, kstuff_patch *patch);
