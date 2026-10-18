// Adapted from EchoStretch/ps4-hen-vtx, commit
// 5e83743ebca4eb7b096fd00eece3152fdf4b19b5. FSELF/FPKG work by flatz, xvortex,
// SiSTRo and the PS4-HEN contributors.

#include <stddef.h>
#include <stdint.h>

#include "offsets.h"
#include "sections.h"
#include "sparse.h"

#include "freebsd_helper.h"

#include "amd_helper.h"
#include "ccp_helper.h"
#include "elf_helper.h"
#include "firmware.h"
#include "pfs_helper.h"
#include "rif_helper.h"
#include "sbl_helper.h"
#include "self_helper.h"

int (*memcmp)(const void *ptr1, const void *ptr2, size_t num) PAYLOAD_BSS;
int (*_sx_xlock)(struct sx *sx, int opts, const char *file,
                 int line) PAYLOAD_BSS;
int (*_sx_xunlock)(struct sx *sx) PAYLOAD_BSS;
void *(*malloc)(unsigned long size, void *type, int flags)PAYLOAD_BSS;
void (*free)(void *addr, void *type) PAYLOAD_BSS;
char *(*strstr)(const char *haystack, const char *needle)PAYLOAD_BSS;
int (*fpu_kern_enter)(struct thread *td, struct fpu_kern_ctx *ctx,
                      uint32_t flags) PAYLOAD_BSS;
int (*fpu_kern_leave)(struct thread *td, struct fpu_kern_ctx *ctx) PAYLOAD_BSS;
void *(*memcpy)(void *dst, const void *src, size_t len)PAYLOAD_BSS;
void *(*memset)(void *s, int c, size_t n)PAYLOAD_BSS;
size_t (*strlen)(const char *str) PAYLOAD_BSS;
int (*printf)(const char *fmt, ...) PAYLOAD_BSS;
void (*eventhandler_register)(void *list, const char *name, void *func,
                              void *arg, int priority) PAYLOAD_BSS;

void *M_TEMP PAYLOAD_BSS;
uint8_t *MINI_SYSCORE_SELF_BINARY PAYLOAD_BSS;
struct proc **ALLPROC PAYLOAD_BSS;
struct sbl_map_list_entry **SBL_DRIVER_MAPPED_PAGES PAYLOAD_BSS;
struct sx *SBL_PFS_SX PAYLOAD_BSS;
struct sbl_key_slot_queue *SBL_KEYMGR_KEY_SLOTS PAYLOAD_BSS;
struct sbl_key_rbtree_entry **SBL_KEYMGR_KEY_RBTREE PAYLOAD_BSS;
uint8_t *SBL_KEYMGR_BUF_VA PAYLOAD_BSS;
uint64_t *SBL_KEYMGR_BUF_GVA PAYLOAD_BSS;
void *FPU_CTX PAYLOAD_BSS;
struct sysent *SYSENT PAYLOAD_BSS;

int (*sceSblACMgrGetPathId)(const char *path) PAYLOAD_BSS;
int (*sceSblServiceMailbox)(unsigned long service_id,
                            uint8_t request[SBL_MSG_SERVICE_MAILBOX_MAX_SIZE],
                            void *response) PAYLOAD_BSS;
int (*sceSblAuthMgrSmIsLoadable2)(
    struct self_context *ctx, struct self_auth_info *old_auth_info, int path_id,
    struct self_auth_info *new_auth_info) PAYLOAD_BSS;
int (*_sceSblAuthMgrGetSelfInfo)(struct self_context *ctx,
                                 struct self_ex_info **info) PAYLOAD_BSS;
void (*_sceSblAuthMgrSmStart)(void **) PAYLOAD_BSS;
int (*sceSblAuthMgrVerifyHeader)(struct self_context *ctx) PAYLOAD_BSS;

extern int
my_sceSblAuthMgrIsLoadable2(struct self_context *ctx,
                            struct self_auth_info *old_auth_info, int path_id,
                            struct self_auth_info *new_auth_info) PAYLOAD_CODE;
extern int my_sceSblAuthMgrVerifyHeader(struct self_context *ctx) PAYLOAD_CODE;
extern int my_sceSblAuthMgrSmLoadSelfSegment__sceSblServiceMailbox(
    unsigned long service_id, uint8_t *request, void *response) PAYLOAD_CODE;
extern int my_sceSblAuthMgrSmLoadSelfBlock__sceSblServiceMailbox(
    unsigned long service_id, uint8_t *request, void *response) PAYLOAD_CODE;
extern int
my_sceSblAuthMgrIsLoadable__sceSblACMgrGetPathId(const char *path) PAYLOAD_CODE;

int (*RsaesPkcs1v15Dec2048CRT)(struct rsa_buffer *out, struct rsa_buffer *in,
                               struct rsa_key *key) PAYLOAD_BSS;
void (*Sha256Hmac)(uint8_t hash[0x20], const uint8_t *data, size_t data_size,
                   const uint8_t *key, int key_size) PAYLOAD_BSS;
int (*AesCbcCfb128Encrypt)(uint8_t *out, const uint8_t *in, size_t data_size,
                           const uint8_t *key, int key_size,
                           uint8_t *iv) PAYLOAD_BSS;
int (*AesCbcCfb128Decrypt)(uint8_t *out, const uint8_t *in, size_t data_size,
                           const uint8_t *key, int key_size,
                           uint8_t *iv) PAYLOAD_BSS;
int (*sceSblDriverSendMsg_0)(struct sbl_msg *msg, size_t size) PAYLOAD_BSS;
int (*sceSblPfsSetKeys)(uint32_t *ekh, uint32_t *skh, uint8_t *eekpfs,
                        struct ekc *eekc, unsigned int pubkey_ver,
                        unsigned int key_ver, struct pfs_header *hdr,
                        size_t hdr_size, unsigned int type,
                        unsigned int finalized,
                        unsigned int is_disc) PAYLOAD_BSS;
int (*sceSblKeymgrSetKeyStorage)(uint64_t key_gpu_va, unsigned int key_size,
                                 uint32_t key_id,
                                 uint32_t key_handle) PAYLOAD_BSS;
int (*sceSblKeymgrSetKeyForPfs)(union sbl_key_desc *key,
                                unsigned int *handle) PAYLOAD_BSS;
int (*sceSblKeymgrCleartKey)(uint32_t kh) PAYLOAD_BSS;
int (*sceSblKeymgrSmCallfunc)(union keymgr_payload *payload) PAYLOAD_BSS;

extern int my_sceSblKeymgrSmCallfunc_npdrm_decrypt_isolated_rif(
    union keymgr_payload *payload) PAYLOAD_CODE;
extern int my_sceSblKeymgrSmCallfunc_npdrm_decrypt_rif_new(
    union keymgr_payload *payload) PAYLOAD_CODE;
extern int
my_sceSblKeymgrSetKeyStorage__sceSblDriverSendMsg(struct sbl_msg *msg,
                                                  size_t size) PAYLOAD_CODE;
extern int my_mountpfs__sceSblPfsSetKeys(
    uint32_t *ekh, uint32_t *skh, uint8_t *eekpfs, struct ekc *eekc,
    unsigned int pubkey_ver, unsigned int key_ver, struct pfs_header *hdr,
    size_t hdr_size, unsigned int type, unsigned int finalized,
    unsigned int is_disc) PAYLOAD_CODE;

#define resolve(name) name = (void *)(kernbase + name##_addr)

PAYLOAD_CODE void resolve_kdlsym() {
  uint64_t kernbase = getkernbase(XFAST_SYSCALL_addr);

  resolve(M_TEMP);
  resolve(MINI_SYSCORE_SELF_BINARY);
  resolve(ALLPROC);
  resolve(SBL_DRIVER_MAPPED_PAGES);
  resolve(SBL_PFS_SX);
  resolve(SBL_KEYMGR_KEY_SLOTS);
  resolve(SBL_KEYMGR_KEY_RBTREE);
  resolve(SBL_KEYMGR_BUF_VA);
  resolve(SBL_KEYMGR_BUF_GVA);
  resolve(FPU_CTX);
  resolve(SYSENT);

  resolve(memcmp);
  resolve(_sx_xlock);
  resolve(_sx_xunlock);
  resolve(malloc);
  resolve(free);
  resolve(strstr);
  resolve(fpu_kern_enter);
  resolve(fpu_kern_leave);
  resolve(memcpy);
  resolve(memset);
  resolve(strlen);
  resolve(printf);
  resolve(eventhandler_register);

  resolve(sceSblACMgrGetPathId);
  resolve(sceSblServiceMailbox);
  resolve(sceSblAuthMgrSmIsLoadable2);
  resolve(_sceSblAuthMgrGetSelfInfo);
  resolve(_sceSblAuthMgrSmStart);
  resolve(sceSblAuthMgrVerifyHeader);

  resolve(sceSblPfsSetKeys);
  resolve(sceSblKeymgrCleartKey);
  resolve(sceSblKeymgrSetKeyForPfs);
  resolve(sceSblKeymgrSetKeyStorage);
  resolve(sceSblKeymgrSmCallfunc);
  resolve(sceSblDriverSendMsg_0);
  resolve(RsaesPkcs1v15Dec2048CRT);
  resolve(AesCbcCfb128Encrypt);
  resolve(AesCbcCfb128Decrypt);
  resolve(Sha256Hmac);
}

extern int my_sceSblKeymgrInvalidateKey__sx_xlock(struct sx *, int,
                                                  const char *,
                                                  int) PAYLOAD_CODE;
extern char __image_end[];
extern struct kstuff_header payload_header;

PAYLOAD_CODE int kstuff_kernel_start(void) {
  uint64_t base = getkernbase(XFAST_SYSCALL_addr);

  resolve_kdlsym();

  for (unsigned i = 0; i < KSTUFF_CALL_COUNT; ++i) {
    const uint8_t *p = (void *)(base + payload_header.firmware.calls[i].offset);
    int32_t rel;

    memcpy(&rel, p + 1, sizeof(rel));

    if (*p != 0xe8 || (uint64_t)(p + 5 + rel) !=
                          base + payload_header.firmware.calls[i].target)
      return 16;
  }

  for (unsigned i = 0; i < sizeof(payload_header.firmware.patches) /
                               sizeof(*payload_header.firmware.patches);
       ++i) {
    const uint8_t *p =
        (void *)(base + payload_header.firmware.patches[i].offset);

    if (memcmp(p, payload_header.firmware.patches[i].bytes, 3) &&
        !(p[0] == 0x55 && p[1] == 0x48 && p[2] == 0x89))
      return 22;
  }

  uint64_t flags = intr_disable();
  uint64_t cr0 = readCr0();

  writeCr0(cr0 & ~X86_CR0_WP);

  for (unsigned i = 0; i < KSTUFF_CALL_COUNT; ++i) {
    uint64_t target = (uint64_t)&payload_header + payload_header.handlers[i];
    int32_t rel = target - (base + payload_header.firmware.calls[i].offset + 5);

    memcpy((void *)(base + payload_header.firmware.calls[i].offset + 1), &rel,
           sizeof(rel));
  }

  for (unsigned i = 0; i < sizeof(payload_header.firmware.patches) /
                               sizeof(*payload_header.firmware.patches);
       ++i)
    memcpy((void *)(base + payload_header.firmware.patches[i].offset),
           payload_header.firmware.patches[i].bytes, 3);

  payload_header.installed = 1;
  writeCr0(cr0);
  intr_restore(flags);

  return 0;
}

struct kstuff_header payload_header PAYLOAD_HEADER = {
    .magic = KSTUFF_MAGIC,
    .entry = (uintptr_t)kstuff_kernel_start,
    .size = (uintptr_t)__image_end,
    .abi = KSTUFF_ABI,
    .handlers =
        {
            (uintptr_t)my_sceSblAuthMgrIsLoadable2,
            (uintptr_t)my_sceSblAuthMgrVerifyHeader,
            (uintptr_t)my_sceSblAuthMgrVerifyHeader,
            (uintptr_t)my_sceSblAuthMgrSmLoadSelfSegment__sceSblServiceMailbox,
            (uintptr_t)my_sceSblAuthMgrSmLoadSelfBlock__sceSblServiceMailbox,
            (uintptr_t)my_sceSblAuthMgrIsLoadable__sceSblACMgrGetPathId,
            (uintptr_t)my_sceSblKeymgrSmCallfunc_npdrm_decrypt_isolated_rif,
            (uintptr_t)my_sceSblKeymgrSmCallfunc_npdrm_decrypt_rif_new,
            (uintptr_t)my_sceSblKeymgrSetKeyStorage__sceSblDriverSendMsg,
            (uintptr_t)my_sceSblKeymgrInvalidateKey__sx_xlock,
            (uintptr_t)my_mountpfs__sceSblPfsSetKeys,
            (uintptr_t)my_mountpfs__sceSblPfsSetKeys,
        },
};
