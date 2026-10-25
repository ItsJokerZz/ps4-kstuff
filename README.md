# ps4-kstuff
A library of patches for PS4 derived from the work of PS4-HEN

Installs the FSELF/FPKG kernel hooks and kernel patches, patches SceShellCore so packages and system versions are accepted, and applies the Remote Play patches. The firmwares in `source/firmware_table.inc` are supported (4.74 to 14.00 at the moment); anything else is left untouched.

## Layout

| Path | What it is |
| --- | --- |
| `kernel/` | Kernel payload: FSELF/FPKG hooks, built with the host `gcc` into `kstuff-kernel.bin` |
| `source/apply.cpp` | Coordinates the patch stages, paralleling the installer entry point in ps4-hen |
| `source/kpayload.cpp`, `source/kernel_exec.c`, `kernel/` | FSELF/FPKG kernel hooks and the kernel payload installer |
| `source/exploit_fixes.cpp` | Installer-time exploit cleanup writes and their generated per-firmware records |
| `source/shellcore.cpp`, `source/remoteplay.cpp` | ShellCore and Remote Play process patches |
| `source/firmware.c`, `headers/firmware.h` | Firmware offsets and shared firmware data types |
| `source/patches.h` | Internal interfaces between the patch modules |
| `source/firmware_table.inc`, `source/remoteplay_table.inc` | Per-firmware offsets, generated from ps4-hen by `tools/generate.py` |
| `source/exploit_fixes_table.inc` | Firmware-specific kernel cleanup patches extracted from the ps4-hen installer |
| `headers/kstuff.h` | Public API |
| `include/` | Kernel helper headers copied unmodified from [Scene-Collective/ps4-hen](https://github.com/Scene-Collective/ps4-hen) |

## API

```c
#include "kstuff.h"

void kstuff_set_logger(void (*sink)(const char *line));
void kstuff_set_patch_hook(int (*hook)(pid_t pid, uintptr_t address,
                                       size_t length, const uint8_t *original));
int kstuff_apply(void);
int kstuff_reapply_shellcore(void);
```

`kstuff_set_logger` is optional; without it, messages go to klog. `kstuff_set_patch_hook` is optional too: the hook is called with the address and original bytes of every process patch just before it is written, and a non-zero return cancels that patch. `kstuff_apply` returns non-zero with `errno` set when something was skipped. The static library is meant to be linked together with [lib-ps-ptrace](https://github.com/ItsJokerZz/lib-ps-ptrace).

## Building

Needs the [PS4 payload SDK](https://github.com/Scene-Collective/ps4-payload-sdk) (`PS4_PAYLOAD_SDK`), a host `gcc`, `xxd` and a lib-ps-ptrace checkout.

```sh
make PTRACE_DIR=../lib-ps-ptrace BUILD=build
```

| Output | Path |
| --- | --- |
| Library | `$(BUILD)/lib/libkstuff.a` |
| Kernel payload | `$(BUILD)/bin/kstuff-kernel.bin` and `.elf` |

`make kernel` builds only the kernel payload and needs nothing but a host `gcc`.

## Syncing with ps4-hen

```sh
sh update.sh            # ps4-hen HEAD
sh update.sh <ref>      # any branch, tag or commit of ps4-hen
```

The script fetches that revision, overwrites `include/` with the listed upstream files, regenerates the firmware and Remote Play tables from `kpayload/`, and imports every firmware-specific write in the installer's `exploit_fixes()` from `installer/source/kpayloads.c`. `kstuff_apply()` runs those cleanup patches before installing the kernel payload, following HEN's installer order. A ShellCore mismatch skips only the ShellCore stage; the independent kernel stages still run. Review the diff and commit it.

The workflow (`.github/workflows/sync-ps4-hen.yml`) polls ps4-hen every six hours, regenerates the imported patch data, and builds the full payload library and kernel payload before updating its sync pull request. The upstream commit is recorded even when generated tables are unchanged, so changes outside the importer still produce a reviewable PR with a link to the upstream diff. The sync branch is updated only when its remote tip is the automation bot's commit, and the update uses a lease to avoid racing another push.

The generator stops before changing tracked files if required offsets, installer values, or `exploit_fixes()` records are missing or have an unrecognized form. Runtime code changes in ps4-hen's `kpayload/source` are surfaced for review but are not copied blindly; a new firmware may also require updates to `menu_jump` in `source/remoteplay.cpp` and `patch_set` in `source/shellcore.cpp` after checking upstream `patch.c`.
