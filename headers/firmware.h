#pragma once

#include <stddef.h>
#include <stdint.h>

#define KSTUFF_MAGIC UINT64_C(0x315546465554534b)
#define KSTUFF_ABI 2
#define KSTUFF_KERNEL_LIMIT 0x10000
#define KSTUFF_CALL_COUNT 12
#define KSTUFF_PATCH_COUNT 3
#define KSTUFF_SHELLCORE_COUNT 17

/* Scene-Collective/ps4-hen. */
struct kstuff_symbols {
  uint32_t XFAST_SYSCALL_addr;
  uint32_t M_TEMP_addr;
  uint32_t MINI_SYSCORE_SELF_BINARY_addr;
  uint32_t ALLPROC_addr;
  uint32_t SBL_DRIVER_MAPPED_PAGES_addr;
  uint32_t SBL_PFS_SX_addr;
  uint32_t SBL_KEYMGR_KEY_SLOTS_addr;
  uint32_t SBL_KEYMGR_KEY_RBTREE_addr;
  uint32_t SBL_KEYMGR_BUF_VA_addr;
  uint32_t SBL_KEYMGR_BUF_GVA_addr;
  uint32_t FPU_CTX_addr;
  uint32_t SYSENT_addr;
  uint32_t memcmp_addr;
  uint32_t _sx_xlock_addr;
  uint32_t _sx_xunlock_addr;
  uint32_t malloc_addr;
  uint32_t free_addr;
  uint32_t strstr_addr;
  uint32_t fpu_kern_enter_addr;
  uint32_t fpu_kern_leave_addr;
  uint32_t memcpy_addr;
  uint32_t memset_addr;
  uint32_t strlen_addr;
  uint32_t printf_addr;
  uint32_t eventhandler_register_addr;
  uint32_t sceSblACMgrGetPathId_addr;
  uint32_t sceSblServiceMailbox_addr;
  uint32_t sceSblAuthMgrSmIsLoadable2_addr;
  uint32_t _sceSblAuthMgrGetSelfInfo_addr;
  uint32_t _sceSblAuthMgrSmStart_addr;
  uint32_t sceSblAuthMgrVerifyHeader_addr;
  uint32_t sceSblPfsSetKeys_addr;
  uint32_t sceSblKeymgrCleartKey_addr;
  uint32_t sceSblKeymgrSetKeyForPfs_addr;
  uint32_t sceSblKeymgrSetKeyStorage_addr;
  uint32_t sceSblKeymgrSmCallfunc_addr;
  uint32_t sceSblDriverSendMsg_0_addr;
  uint32_t RsaesPkcs1v15Dec2048CRT_addr;
  uint32_t AesCbcCfb128Encrypt_addr;
  uint32_t AesCbcCfb128Decrypt_addr;
  uint32_t Sha256Hmac_addr;
};

struct kstuff_call_site {
  uint32_t offset, target;
};

struct kstuff_kernel_patch {
  uint32_t offset;
  uint8_t bytes[3];
};

struct kstuff_exploit_patch {
  uint32_t offset;
  uint8_t length;
  uint8_t bytes[16];
};

struct kstuff_firmware {
  uint32_t version, pmap_protect, pmap_check, pmap_store;
  struct kstuff_symbols symbols;
  struct kstuff_call_site calls[KSTUFF_CALL_COUNT];
  struct kstuff_kernel_patch patches[KSTUFF_PATCH_COUNT];
  uint32_t shellcore[KSTUFF_SHELLCORE_COUNT];
};

struct kstuff_header {
  uint64_t magic, entry, size, abi, installed, image_hash;
  uint64_t handlers[KSTUFF_CALL_COUNT];
  struct kstuff_firmware firmware;
};

#ifdef __cplusplus
extern "C" {
#endif

const struct kstuff_firmware *kstuff_firmware_for(uint32_t sdk_version);

#ifdef __cplusplus
}
#endif
