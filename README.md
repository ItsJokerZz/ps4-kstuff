# ps4-kstuff
A library of patches for PS4 derived from the work of PS4-HEN

Installs the FSELF/FPKG kernel hooks and kernel patches, patches SceShellCore so packages and system versions are accepted, and applies the Remote Play patches. The firmwares in `source/firmware_table.inc` are supported (4.74 to 14.00 at the moment); anything else is left untouched.

## Layout

| Path | What it is |
| --- | --- |
| `kernel/` | Kernel payload: FSELF/FPKG hooks, built with the host `gcc` into `kstuff-kernel.bin` |
| `source/` | Userland: kernel installer, ShellCore and Remote Play patching |
| `source/*_table.inc` | Per-firmware offsets, generated from ps4-hen by `tools/generate.py` |
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

The script fetches that revision, overwrites `include/` with the listed upstream files, regenerates the two `source/*_table.inc` files (Python 3, standard library only) and rewrites `UPSTREAM`. Review the diff and commit it.

A daily workflow (`.github/workflows/sync-ps4-hen.yml`) does the same and opens a pull request when anything changed, with a link to the upstream diff and the result of `make kernel`. Code changes in ps4-hen's `kpayload/source` are not ported automatically, and a new firmware may also need `menu_jump` in `source/remoteplay.cpp` and `patch_set` in `source/shellcore.cpp` checked against ps4-hen's `patch.c`.
