#include "firmware.h"
#include <stddef.h>

struct kernel_args {
  void *fn;
  uintptr_t base, image, size, unused[2];
};

int kstuff_kernel_exec(void *td, struct kernel_args *args) {
  (void)td;

  uintptr_t base = args->base, image = args->image;
  struct kstuff_header *header = (void *)image;
  const struct kstuff_firmware *fw = &header->firmware;
  volatile uint8_t *check = (void *)(base + fw->pmap_check);

  if (!args->size || args->size > KSTUFF_KERNEL_LIMIT ||
      header->magic != KSTUFF_MAGIC || header->abi != KSTUFF_ABI ||
      header->entry < sizeof(*header) || header->entry >= args->size ||
      *check != 0x75)
    return 22;

  void (*pmap_protect)(void *, uintptr_t, uintptr_t, uint8_t) =
      (void *)(base + fw->pmap_protect);

  uintptr_t cr0;

  __asm__ volatile("mov %%cr0, %0" : "=r"(cr0));

  uintptr_t writable = cr0 & ~(uintptr_t)(1 << 16);

  __asm__ volatile("mov %0, %%cr0" : : "r"(writable) : "memory");
  *check = 0xeb;
  pmap_protect((void *)(base + fw->pmap_store), image & ~(uintptr_t)0x3fff,
               (image + args->size + 0x3fff) & ~(uintptr_t)0x3fff, 7);
  *check = 0x75;
  __asm__ volatile("mov %0, %%cr0" : : "r"(cr0) : "memory");

  return ((int (*)(void))(image + header->entry))();
}
