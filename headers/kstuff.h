#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

int kstuff_apply(void);
int kstuff_reapply_shellcore(void);
void kstuff_set_logger(void (*sink)(const char *line));
void kstuff_set_patch_hook(int (*hook)(pid_t pid, uintptr_t address,
                                       size_t length, const uint8_t *original));

#ifdef __cplusplus
}
#endif
