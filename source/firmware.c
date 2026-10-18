#include "firmware.h"

static const struct kstuff_firmware firmwares[] = {
#include "firmware_table.inc"
};

const struct kstuff_firmware *kstuff_firmware_for(uint32_t sdk_version) {
  unsigned bcd = sdk_version >> 16, version = 0, multiplier = 1;

  for (int i = 0; i < 4; ++i, bcd >>= 4, multiplier *= 10) {
    unsigned digit = bcd & 15;

    if (digit > 9)
      return 0;

    version += digit * multiplier;
  }

  for (unsigned i = 0; i < sizeof(firmwares) / sizeof(*firmwares); ++i)
    if (firmwares[i].version == version)
      return &firmwares[i];

  return 0;
}
