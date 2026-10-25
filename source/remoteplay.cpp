#include "firmware.h"
#include "patches.h"
#include "support.h"
#include <cerrno>
#include <cstring>
#include <ps4/kernel.h>

extern "C" {
#include "ptrace.h"
}

/* Scene-Collective/ps4-hen, Remote
 * Play patches (credits there to Aida). */
struct remoteplay_offsets {
  uint32_t version, menu, flag, branch;
};

static const remoteplay_offsets offsets[] = {
#include "remoteplay_table.inc"
};

struct remoteplay_patch {
  uint32_t offset;
  uint8_t size, original[5], mask[5], replacement[5];
};

enum remoteplay_patch_state {
  REMOTEPLAY_PATCH_ERROR = -1,
  REMOTEPLAY_PATCH_READY,
  REMOTEPLAY_PATCH_APPLIED,
  REMOTEPLAY_PATCH_FOREIGN,
};

static const char *menu_jump(uint32_t version) {
  if (version == 474)
    return "\xe9\x22\x02\x00\x00";

  if (version >= 500 && version <= 507)
    return "\xe9\x82\x02\x00\x00";

  if (version >= 550 && version <= 620)
    return "\xe9\xb8\x02\x00\x00";

  if (version >= 650 && version <= 904)
    return "\xe9\xba\x02\x00\x00";

  if (version >= 950 && version <= 960)
    return "\xe9\xa2\x02\x00\x00";

  return "\xe9\x5c\x02\x00\x00";
}

static remoteplay_patch make(uint32_t offset, uint8_t size,
                             const char *original, const char *mask,
                             const char *replacement) {
  remoteplay_patch p{};

  p.offset = offset;
  p.size = size;
  memcpy(p.original, original, size);
  memcpy(p.mask, mask, size);
  memcpy(p.replacement, replacement, size);

  return p;
}

static remoteplay_patch_state check_patch(pid_t pid, uintptr_t base,
                                          const remoteplay_patch &patch,
                                          uint8_t *bytes) {
  if (!patch.offset || patch.offset > 0x4000000 ||
      pt_copyout(pid, base + patch.offset, bytes, patch.size))
    return REMOTEPLAY_PATCH_ERROR;

  if (!memcmp(bytes, patch.replacement, patch.size))
    return REMOTEPLAY_PATCH_APPLIED;

  for (unsigned i = 0; i < patch.size; ++i)
    if ((bytes[i] & patch.mask[i]) != patch.original[i])
      return REMOTEPLAY_PATCH_FOREIGN;

  return REMOTEPLAY_PATCH_READY;
}

static unsigned apply(pid_t pid, uintptr_t base,
                      const remoteplay_patch *patches, unsigned count,
                      const char *where) {
  unsigned ready = 0;

  if (pid <= 0 || !base || pt_attach(pid)) {
    kstuff_log("[RemotePlay] %s is not reachable (pid=%d base=%#lx)\n", where,
               (int)pid, (unsigned long)base);
    return 0;
  }

  for (unsigned i = 0; i < count; ++i) {
    const remoteplay_patch &p = patches[i];
    uint8_t bytes[5]{};
    remoteplay_patch_state state = check_patch(pid, base, p, bytes);

    if (state == REMOTEPLAY_PATCH_ERROR) {
      kstuff_log("[RemotePlay] %s +%#x cannot be read\n", where, p.offset);
      continue;
    }

    if (state == REMOTEPLAY_PATCH_APPLIED) {
      ++ready;
      continue;
    }

    if (state == REMOTEPLAY_PATCH_FOREIGN) {
      kstuff_log(
          "[RemotePlay] Unexpected %s bytes at +%#x (%02x %02x %02x %02x "
          "%02x); unchanged\n",
          where, p.offset, bytes[0], bytes[1], bytes[2], bytes[3], bytes[4]);
      continue;
    }

    kstuff_patch change{};

    change.address = base + p.offset;
    change.length = p.size;
    memcpy(change.replacement, p.replacement, p.size);

    if (kstuff_patch_prepare(pid, &change) ||
        kstuff_patch_commit(pid, &change)) {
      kstuff_log("[RemotePlay] %s +%#x could not be written (errno=%d)\n",
                 where, p.offset, errno);
      continue;
    }

    ++ready;
  }

  pt_detach(pid, 0);

  return ready;
}

void kstuff_remote_play(uint32_t version) {
  const remoteplay_offsets *fw = nullptr;

  for (const auto &entry : offsets)
    if (entry.version == version)
      fw = &entry;

  if (!fw || !fw->menu || !fw->flag || !fw->branch) {
    kstuff_log("[RemotePlay] No patches known for firmware %u.%02u\n",
               version / 100, version % 100);
    return;
  }

  const remoteplay_patch menu =
      make(fw->menu, 5, "\xbf\0\0\0\0", "\xff\0\0\0\0", menu_jump(version));
  pid_t shellui = kstuff_find_pid("SceShellUI");
  uint32_t handle = 0;
  uintptr_t app = 0;

  if (shellui > 0 && !kernel_dynlib_handle(shellui,
                                           version < 500 ? "libSceVsh_aot.sprx"
                                                         : "app.exe.sprx",
                                           &handle))
    app = kernel_dynlib_mapbase_addr(shellui, handle);

  unsigned menu_ready = apply(shellui, app, &menu, 1, "SceShellUI");

  const remoteplay_patch service[] = {
      make(fw->flag, 1, "\0", "\xff", "\x01"),
      make(fw->branch, 2, "\x48\x8d", "\xfb\xff", "\xeb\x1e"),
  };

  pid_t daemon = kstuff_find_pid("SceRemotePlay");
  uintptr_t executable = daemon > 0 ? kernel_dynlib_mapbase_addr(daemon, 0) : 0;
  unsigned service_ready =
      apply(daemon, executable, service, 2, "SceRemotePlay");

  kstuff_log("[RemotePlay] Menu patch %u of 1, service patches %u of 2\n",
             menu_ready, service_ready);
}
