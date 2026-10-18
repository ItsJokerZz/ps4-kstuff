#pragma once

#ifdef __cplusplus
extern "C" {
#endif

int kstuff_apply(void);
int kstuff_reapply_shellcore(void);
void kstuff_set_logger(void (*sink)(const char *line));

#ifdef __cplusplus
}
#endif
