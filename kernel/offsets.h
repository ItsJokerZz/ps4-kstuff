#pragma once

#include "firmware.h"

extern struct kstuff_header payload_header;

#define XFAST_SYSCALL_addr (payload_header.firmware.symbols.XFAST_SYSCALL_addr)
#define M_TEMP_addr (payload_header.firmware.symbols.M_TEMP_addr)
#define MINI_SYSCORE_SELF_BINARY_addr                                          \
  (payload_header.firmware.symbols.MINI_SYSCORE_SELF_BINARY_addr)
#define ALLPROC_addr (payload_header.firmware.symbols.ALLPROC_addr)
#define SBL_DRIVER_MAPPED_PAGES_addr                                           \
  (payload_header.firmware.symbols.SBL_DRIVER_MAPPED_PAGES_addr)
#define SBL_PFS_SX_addr (payload_header.firmware.symbols.SBL_PFS_SX_addr)
#define SBL_KEYMGR_KEY_SLOTS_addr                                              \
  (payload_header.firmware.symbols.SBL_KEYMGR_KEY_SLOTS_addr)
#define SBL_KEYMGR_KEY_RBTREE_addr                                             \
  (payload_header.firmware.symbols.SBL_KEYMGR_KEY_RBTREE_addr)
#define SBL_KEYMGR_BUF_VA_addr                                                 \
  (payload_header.firmware.symbols.SBL_KEYMGR_BUF_VA_addr)
#define SBL_KEYMGR_BUF_GVA_addr                                                \
  (payload_header.firmware.symbols.SBL_KEYMGR_BUF_GVA_addr)
#define FPU_CTX_addr (payload_header.firmware.symbols.FPU_CTX_addr)
#define SYSENT_addr (payload_header.firmware.symbols.SYSENT_addr)
#define memcmp_addr (payload_header.firmware.symbols.memcmp_addr)
#define _sx_xlock_addr (payload_header.firmware.symbols._sx_xlock_addr)
#define _sx_xunlock_addr (payload_header.firmware.symbols._sx_xunlock_addr)
#define malloc_addr (payload_header.firmware.symbols.malloc_addr)
#define free_addr (payload_header.firmware.symbols.free_addr)
#define strstr_addr (payload_header.firmware.symbols.strstr_addr)
#define fpu_kern_enter_addr                                                    \
  (payload_header.firmware.symbols.fpu_kern_enter_addr)
#define fpu_kern_leave_addr                                                    \
  (payload_header.firmware.symbols.fpu_kern_leave_addr)
#define memcpy_addr (payload_header.firmware.symbols.memcpy_addr)
#define memset_addr (payload_header.firmware.symbols.memset_addr)
#define strlen_addr (payload_header.firmware.symbols.strlen_addr)
#define printf_addr (payload_header.firmware.symbols.printf_addr)
#define eventhandler_register_addr                                             \
  (payload_header.firmware.symbols.eventhandler_register_addr)
#define sceSblACMgrGetPathId_addr                                              \
  (payload_header.firmware.symbols.sceSblACMgrGetPathId_addr)
#define sceSblServiceMailbox_addr                                              \
  (payload_header.firmware.symbols.sceSblServiceMailbox_addr)
#define sceSblAuthMgrSmIsLoadable2_addr                                        \
  (payload_header.firmware.symbols.sceSblAuthMgrSmIsLoadable2_addr)
#define _sceSblAuthMgrGetSelfInfo_addr                                         \
  (payload_header.firmware.symbols._sceSblAuthMgrGetSelfInfo_addr)
#define _sceSblAuthMgrSmStart_addr                                             \
  (payload_header.firmware.symbols._sceSblAuthMgrSmStart_addr)
#define sceSblAuthMgrVerifyHeader_addr                                         \
  (payload_header.firmware.symbols.sceSblAuthMgrVerifyHeader_addr)
#define sceSblPfsSetKeys_addr                                                  \
  (payload_header.firmware.symbols.sceSblPfsSetKeys_addr)
#define sceSblKeymgrCleartKey_addr                                             \
  (payload_header.firmware.symbols.sceSblKeymgrCleartKey_addr)
#define sceSblKeymgrSetKeyForPfs_addr                                          \
  (payload_header.firmware.symbols.sceSblKeymgrSetKeyForPfs_addr)
#define sceSblKeymgrSetKeyStorage_addr                                         \
  (payload_header.firmware.symbols.sceSblKeymgrSetKeyStorage_addr)
#define sceSblKeymgrSmCallfunc_addr                                            \
  (payload_header.firmware.symbols.sceSblKeymgrSmCallfunc_addr)
#define sceSblDriverSendMsg_0_addr                                             \
  (payload_header.firmware.symbols.sceSblDriverSendMsg_0_addr)
#define RsaesPkcs1v15Dec2048CRT_addr                                           \
  (payload_header.firmware.symbols.RsaesPkcs1v15Dec2048CRT_addr)
#define AesCbcCfb128Encrypt_addr                                               \
  (payload_header.firmware.symbols.AesCbcCfb128Encrypt_addr)
#define AesCbcCfb128Decrypt_addr                                               \
  (payload_header.firmware.symbols.AesCbcCfb128Decrypt_addr)
#define Sha256Hmac_addr (payload_header.firmware.symbols.Sha256Hmac_addr)
