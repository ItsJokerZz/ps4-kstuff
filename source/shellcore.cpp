#include "firmware.h"
#include "kstuff.h"
#include "patches.h"
#include "support.h"
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ps4/kernel.h>
#include <vector>

extern "C" {
#include "ptrace.h"
}

struct shellcore_patch {
  uint32_t offset;
  uint8_t size, original[8], mask[8], replacement[8];
};

static std::vector<shellcore_patch> patch_set(const kstuff_firmware &fw) {
  std::vector<shellcore_patch> patches;

  auto add = [&](unsigned index, uint8_t size, const char *original,
                 const char *mask, const char *replacement) {
    shellcore_patch p{};

    p.offset = fw.shellcore[index];
    p.size = size;
    memcpy(p.original, original, size);
    memcpy(p.mask, mask, size);
    memcpy(p.replacement, replacement, size);
    patches.push_back(p);
  };

  for (unsigned i = 0; i < 8; ++i)
    add(i, 5, "\xe8\0\0\0\0", "\xff\0\0\0\0", "\x31\xc0\x90\x90\x90");

  add(8, 5, "\xe8\0\0\0\0", "\xff\0\0\0\0", "\x31\xc0\xff\xc0\x90");

  add(9, 8, "\x85\xc0\x0f\x85\0\0\0\0", "\xff\xff\xff\xff\0\0\0\0",
      fw.version <= 620 ? "\xe9\x96\0\0\0\x90\x90\x90"
                        : "\xe9\x98\0\0\0\x90\x90\x90");
  add(10, 5, "fake", "\xff\xff\xff\xff\xff", "free");
  add(11, 1, "\x01", "\xff", "\0");
  add(12, 1, "\x70", "\xf0", "\xeb");

  if (fw.version >= 500 && fw.version <= 904)
    add(13, 2, "\x0f\x80", "\xff\xf0", "\x90\xe9");

  add(14, 1, "\x70", "\xf0", "\xeb");
  add(15, 1, "\x70", "\xf0", "\xeb");
  add(16, 4, "\x55\x48\x89\xe5", "\xff\xff\xff\xff", "\x48\x31\xc0\xc3");

  return patches;
}

static bool is_foreign(const shellcore_patch &p, const uint8_t *bytes) {
  static const uint8_t skipped_call[] = {0x31, 0xc0, 0xeb, 0x01};

  if (p.original[0] == 0xe8)
    return !memcmp(bytes, skipped_call, sizeof(skipped_call));

  if (p.size != 8)
    return false;

  const uint8_t padded_jump[] = {0x90, 0x90, 0x90, 0xe9,
                                 static_cast<uint8_t>(p.replacement[1] - 3),
                                 0x00, 0x00, 0x00};

  return !memcmp(bytes, p.replacement, 5) ||
         !memcmp(bytes, padded_jump, sizeof(padded_jump));
}

static int check(pid_t pid, uintptr_t base,
                 const std::vector<shellcore_patch> &patches) {
  if (pid <= 0 || !base) {
    errno = ESRCH;
    return -1;
  }

  bool mismatch = false;

  for (const auto &p : patches) {
    uint8_t bytes[8];

    if (!p.offset || p.offset == 0xdeadc0de || p.offset > 0x4000000) {
      errno = EINVAL;
      return -1;
    }

    if (pt_copyout(pid, base + p.offset, bytes, p.size))
      return -1;

    if (!memcmp(bytes, p.replacement, p.size) || is_foreign(p, bytes))
      continue;

    for (unsigned i = 0; i < p.size; ++i)
      if ((bytes[i] & p.mask[i]) != p.original[i]) {
        char hex[3 * sizeof(bytes) + 1] = "";

        for (unsigned j = 0; j < p.size; ++j)
          snprintf(hex + 3 * j, 4, " %02x", bytes[j]);

        kstuff_log(
            "[Kstuff] Unexpected ShellCore bytes at +%#x:%s; unchanged\n",
            p.offset, hex);
        mismatch = true;

        break;
      }
  }

  if (mismatch) {
    errno = EINVAL;
    return -1;
  }

  return 0;
}

int kstuff_check_shellcore(const kstuff_firmware &fw) {
  pid_t pid = kstuff_find_pid("SceShellCore");
  uintptr_t base = pid > 0 ? kernel_dynlib_mapbase_addr(pid, 0) : 0;
  auto patches = patch_set(fw);

  if (pid <= 0 || !base || pt_attach(pid))
    return -1;

  int result = check(pid, base, patches), saved = errno;
  int detached = pt_detach(pid, 0);

  if (result) {
    errno = saved;
    return -1;
  }

  return detached;
}

int kstuff_patch_shellcore(const kstuff_firmware &fw) {
  auto patches = patch_set(fw);
  pid_t pid = kstuff_find_pid("SceShellCore");
  uintptr_t base = pid > 0 ? kernel_dynlib_mapbase_addr(pid, 0) : 0;

  if (pid <= 0 || !base || pt_attach(pid))
    return -1;

  std::vector<kstuff_patch> changes(patches.size());
  int result = check(pid, base, patches);
  size_t changed = 0, kept = 0;

  for (const auto &p : patches) {
    if (result)
      break;

    uint8_t bytes[8];

    if (pt_copyout(pid, base + p.offset, bytes, p.size)) {
      result = -1;
      break;
    }

    if (!memcmp(bytes, p.replacement, p.size))
      continue;

    if (is_foreign(p, bytes)) {
      ++kept;
      continue;
    }

    auto &change = changes[changed];

    change.address = base + p.offset;
    change.length = p.size;
    memcpy(change.replacement, p.replacement, p.size);

    if ((result = kstuff_patch_prepare(pid, &change)))
      break;

    ++changed;
    result = kstuff_patch_commit(pid, &change);
  }

  int saved = errno;

  if (result)
    for (size_t i = changed; i-- > 0;)
      if (changes[i].installed && kstuff_patch_restore(pid, &changes[i]))
        kstuff_log("[Kstuff] ShellCore rollback failed at %#lx\n",
                   changes[i].address);

  int detached = pt_detach(pid, 0);

  if (result) {
    errno = saved;
    return -1;
  }

  if (detached)
    return -1;

  kstuff_log("[Kstuff] Verified %zu ShellCore package/version patches (%zu "
             "applied, %zu kept from another HEN)\n",
             patches.size(), changed, kept);

  return 0;
}

int kstuff_reapply_shellcore() {
  const kstuff_firmware *fw = kstuff_firmware_for(kernel_get_fw_version());

  if (!fw) {
    errno = ENOTSUP;
    return -1;
  }

  return kstuff_check_shellcore(*fw) ? -1 : kstuff_patch_shellcore(*fw);
}
