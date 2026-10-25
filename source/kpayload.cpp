#include "firmware.h"
#include "kstuff.h"
#include "kstuff_kernel.h"
#include "patches.h"
#include "support.h"
#include <cerrno>
#include <cstring>
#include <elf.h>
#include <ps4/kernel.h>
#include <vector>

extern "C" int kstuff_kernel_exec(void *, void *);
extern "C" int kexec(int (*)(void *, void *), ...);

static uint64_t image_hash(const uint8_t *data, size_t size) {
  uint64_t hash = UINT64_C(14695981039346656037);

  for (size_t i = 0; i < size; ++i)
    hash = (hash ^ data[i]) * UINT64_C(1099511628211);

  return hash;
}

static int kernel_patches_ready(uintptr_t base, const kstuff_firmware &fw,
                                bool installed) {
  for (const auto &patch : fw.patches) {
    uint8_t bytes[3];

    if (kernel_copyout(base + patch.offset, bytes, sizeof(bytes)))
      return -1;

    if (!memcmp(bytes, patch.bytes, sizeof(bytes)))
      continue;

    static const uint8_t prologue[] = {0x55, 0x48, 0x89};

    if (installed || memcmp(bytes, prologue, sizeof(bytes))) {
      kstuff_log("[Kstuff] Unexpected kernel bytes at +%#x; unchanged\n",
                 patch.offset);
      errno = EINVAL;
      return -1;
    }
  }

  return 0;
}

static int check_calls(uintptr_t base, uintptr_t destination,
                       const kstuff_firmware &fw, const kstuff_header &image,
                       bool installed) {
  for (size_t i = 0; i < KSTUFF_CALL_COUNT; ++i) {
    uint8_t bytes[5];

    if (kernel_copyout(base + fw.calls[i].offset, bytes, sizeof(bytes)))
      return -1;

    int32_t rel;

    memcpy(&rel, bytes + 1, sizeof(rel));

    uintptr_t actual = base + fw.calls[i].offset + 5 + (intptr_t)rel;
    uintptr_t expected =
        installed ? destination + image.handlers[i] : base + fw.calls[i].target;

    if (bytes[0] != 0xe8 || actual != expected) {
      kstuff_log("[Kstuff] Hook conflict at +%#x (target=%#lx expected=%#lx); "
                 "unchanged\n",
                 fw.calls[i].offset, (unsigned long)actual,
                 (unsigned long)expected);
      errno = EBUSY;
      return -1;
    }
  }

  return 0;
}

static int hooked_calls(uintptr_t base, const kstuff_firmware &fw) {
  int hooked = 0;

  for (const auto &call : fw.calls) {
    uint8_t bytes[5];

    if (kernel_copyout(base + call.offset, bytes, sizeof(bytes)))
      return -1;

    int32_t rel;

    memcpy(&rel, bytes + 1, sizeof(rel));

    uintptr_t actual = base + call.offset + 5 + (intptr_t)rel;

    if (bytes[0] == 0xe8 && actual != base + call.target)
      ++hooked;
  }

  return hooked;
}

static int resident_storage(uintptr_t base, uintptr_t &destination) {
  constexpr uint64_t file_base = UINT64_C(0xffffffff82200000);
  Elf64_Ehdr eh{};

  if (kernel_copyout(base, &eh, sizeof(eh)))
    return -1;

  if (memcmp(eh.e_ident, ELFMAG, SELFMAG) ||
      eh.e_ident[EI_CLASS] != ELFCLASS64 ||
      eh.e_phentsize != sizeof(Elf64_Phdr) || !eh.e_phnum || eh.e_phnum > 32 ||
      eh.e_phoff > 0x4000) {
    errno = ENOEXEC;
    return -1;
  }

  Elf64_Phdr dynamic{};

  for (unsigned i = 0; i < eh.e_phnum; ++i) {
    Elf64_Phdr ph{};

    if (kernel_copyout(base + eh.e_phoff + i * sizeof(ph), &ph, sizeof(ph)))
      return -1;

    if (ph.p_type == PT_DYNAMIC)
      dynamic = ph;
  }

  if (dynamic.p_vaddr < base || dynamic.p_vaddr - base > 0x4000000 ||
      dynamic.p_filesz < 16 || dynamic.p_filesz > 0x4000 ||
      dynamic.p_filesz % sizeof(Elf64_Dyn)) {
    errno = ENOEXEC;
    return -1;
  }

  uint64_t rela = 0, size = 0;

  for (unsigned i = 0; i < dynamic.p_filesz / sizeof(Elf64_Dyn); ++i) {
    Elf64_Dyn d{};

    if (kernel_copyout(dynamic.p_vaddr + i * sizeof(d), &d, sizeof(d)))
      return -1;

    if (!d.d_tag)
      break;

    if (d.d_tag == 0x6100002f)
      rela = d.d_un.d_val;

    if (d.d_tag == 0x61000031)
      size = d.d_un.d_val;
  }

  if (rela < file_base || rela - file_base > 0x4000000 ||
      size < KSTUFF_KERNEL_LIMIT || size > 0x4000000 ||
      rela - file_base + size > 0x4000000) {
    errno = ENOEXEC;
    return -1;
  }

  destination = base + (rela - file_base);

  return 0;
}

int kstuff_install_kernel_payload(uintptr_t base, const kstuff_firmware &fw) {
  uintptr_t destination = 0;

  if (resident_storage(base, destination))
    return -1;

  kstuff_header current{};

  if (kstuff_kernel_len < sizeof(kstuff_header) ||
      kstuff_kernel_len > KSTUFF_KERNEL_LIMIT) {
    errno = ENOEXEC;
    return -1;
  }

  std::vector<uint8_t> payload(kstuff_kernel,
                               kstuff_kernel + kstuff_kernel_len);
  auto &image = *reinterpret_cast<kstuff_header *>(payload.data());

  if (image.magic != KSTUFF_MAGIC || image.abi != KSTUFF_ABI ||
      image.size != payload.size() || image.entry < sizeof(image) ||
      image.entry >= image.size) {
    errno = ENOEXEC;
    return -1;
  }

  for (auto offset : image.handlers)
    if (offset < sizeof(image) || offset >= image.size) {
      errno = ENOEXEC;
      return -1;
    }

  image.firmware = fw;
  image.image_hash = image_hash(payload.data(), payload.size());

  if (kernel_copyout(destination, &current, sizeof(current)))
    return -1;

  if (current.magic == KSTUFF_MAGIC) {
    if (current.abi != KSTUFF_ABI || current.size != image.size ||
        current.entry != image.entry ||
        current.image_hash != image.image_hash || current.installed != 1 ||
        memcmp(current.handlers, image.handlers, sizeof(image.handlers)) ||
        memcmp(&current.firmware, &fw, sizeof(fw))) {
      kstuff_log("[Kstuff] Different or incomplete resident module; reboot "
                 "required\n");
      errno = EBUSY;
      return -1;
    }

    if (check_calls(base, destination, fw, current, true) ||
        kernel_patches_ready(base, fw, true))
      return -1;

    kstuff_log(
        "[Kstuff] Resident FSELF/FPKG hooks verified; reusing this boot's "
        "module\n");

    return 0;
  }

  if (hooked_calls(base, fw) == KSTUFF_CALL_COUNT) {
    kstuff_log("[Kstuff] All %d FSELF/FPKG call sites are already hooked by "
               "another HEN; keeping its hooks\n",
               KSTUFF_CALL_COUNT);

    return 0;
  }

  if (check_calls(base, destination, fw, image, false) ||
      kernel_patches_ready(base, fw, false))
    return -1;

  Elf64_Rela relocation{};
  uint8_t pmap[2];

  if (kernel_copyout(destination, &relocation, sizeof(relocation)) ||
      kernel_copyout(base + fw.pmap_check, pmap, sizeof(pmap)))
    return -1;

  constexpr uint64_t file_base = UINT64_C(0xffffffff82200000);

  if (relocation.r_offset < file_base ||
      relocation.r_offset - file_base >= 0x4000000 ||
      ELF64_R_TYPE(relocation.r_info) != R_X86_64_RELATIVE || pmap[0] != 0x75 ||
      pmap[1] != 0x0f) {
    kstuff_log("[Kstuff] Resident storage or pmap is not stock; installation "
               "declined\n");
    errno = EBUSY;
    return -1;
  }

  std::vector<uint8_t> saved(payload.size()), verified(payload.size());

  if (kernel_copyout(destination, saved.data(), saved.size()))
    return -1;

  int result = kernel_copyin(payload.data(), destination, payload.size());

  if (!result)
    result = kernel_copyout(destination, verified.data(), verified.size());

  if (result || memcmp(verified.data(), payload.data(), payload.size())) {
    int error = errno ? errno : EIO;

    kernel_copyin(saved.data(), destination, saved.size());
    errno = error;

    return -1;
  }

  kstuff_log("[Kstuff] Firmware %u.%02u image verified (%zu bytes); entering "
             "installer\n",
             fw.version / 100, fw.version % 100, payload.size());
  result = kexec(kstuff_kernel_exec, base, destination,
                 (uintptr_t)payload.size(), (uintptr_t)0, (uintptr_t)0);

  if (result || kernel_copyout(destination, &current, sizeof(current)) ||
      current.installed != 1) {
    int error = errno ? errno : EIO;

    if (!check_calls(base, destination, fw, image, false))
      kernel_copyin(saved.data(), destination, saved.size());

    kstuff_log("[Kstuff] Kernel installation failed: result=%d errno=%d\n",
               result, error);
    errno = error;

    return -1;
  }

  if (check_calls(base, destination, fw, image, true) ||
      kernel_patches_ready(base, fw, true))
    return -1;

  kstuff_log(
      "[Kstuff] Installed and verified 12 resident FSELF/FPKG hooks and 3 "
      "kernel patches\n");

  return 0;
}

