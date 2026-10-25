#pragma once

#include "firmware.h"

int kstuff_install_kernel_payload(uintptr_t base, const kstuff_firmware &fw);
int kstuff_check_exploit_fixes(uintptr_t base, uint32_t version,
                               bool *already_applied);
int kstuff_apply_exploit_fixes(uintptr_t base, uint32_t version);
int kstuff_check_shellcore(const kstuff_firmware &fw);
int kstuff_patch_shellcore(const kstuff_firmware &fw);
void kstuff_remote_play(uint32_t version);
