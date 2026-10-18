#!/usr/bin/env python3
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

CALLS = [
    ("sceSblAuthMgrIsLoadable2_hook", "sceSblAuthMgrSmIsLoadable2_addr"),
    ("sceSblAuthMgrVerifyHeader_hook1", "sceSblAuthMgrVerifyHeader_addr"),
    ("sceSblAuthMgrVerifyHeader_hook2", "sceSblAuthMgrVerifyHeader_addr"),
    ("sceSblAuthMgrSmLoadSelfSegment__sceSblServiceMailbox_hook", "sceSblServiceMailbox_addr"),
    ("sceSblAuthMgrSmLoadSelfBlock__sceSblServiceMailbox_hook", "sceSblServiceMailbox_addr"),
    ("sceSblAuthMgrIsLoadable__sceSblACMgrGetPathId_hook", "sceSblACMgrGetPathId_addr"),
    ("sceSblKeymgrSmCallfunc_npdrm_decrypt_isolated_rif_hook", "sceSblKeymgrSmCallfunc_addr"),
    ("sceSblKeymgrSmCallfunc_npdrm_decrypt_rif_new_hook", "sceSblKeymgrSmCallfunc_addr"),
    ("sceSblKeymgrSetKeyStorage__sceSblDriverSendMsg_hook", "sceSblDriverSendMsg_0_addr"),
    ("sceSblKeymgrInvalidateKey__sx_xlock_hook", "_sx_xlock_addr"),
    ("mountpfs__sceSblPfsSetKeys_hook1", "sceSblPfsSetKeys_addr"),
    ("mountpfs__sceSblPfsSetKeys_hook2", "sceSblPfsSetKeys_addr"),
]

PATCHES = [
    ("PFS_SIGNATURE_CHECK_PATCH", "0x31, 0xc0, 0xc3"),
    ("DEBUG_RIF_PATCH_1", "0xb0, 1, 0xc3"),
    ("DEBUG_RIF_PATCH_2", "0xb0, 1, 0xc3"),
]

SHELLCORE = [
    "sceKernelIsGenuineCEX_patch1",
    "sceKernelIsGenuineCEX_patch2",
    "sceKernelIsGenuineCEX_patch3",
    "sceKernelIsGenuineCEX_patch4",
    "nidf_libSceDipsw_patch1",
    "nidf_libSceDipsw_patch2",
    "nidf_libSceDipsw_patch3",
    "nidf_libSceDipsw_patch4",
    "enable_data_mount_patch",
    "enable_fpkg_patch",
    "fake_free_patch",
    "pkg_installer_patch",
    "ext_hdd_patch",
    "check_disc_root_param_patch",
    "app_installer_patch",
    "check_system_version",
    "check_title_system_update_patch",
]

REMOTE_PLAY = ["remote_play_menu_patch", "SceRemotePlay_patch1", "SceRemotePlay_patch2"]


def fail(message):
    sys.exit(f"generate.py: {message}")


def symbol_names():
    text = (ROOT / "headers" / "firmware.h").read_text()
    body = re.search(r"struct kstuff_symbols \{(.*?)\};", text, re.S)

    if not body:
        fail("struct kstuff_symbols not found in headers/firmware.h")

    return re.findall(r"uint32_t (\w+);", body.group(1))


def strip_comments(text):
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)

    return re.sub(r"//[^\n]*", "", text)


def read_offsets(path):
    text = strip_comments(path.read_text())

    return {name: int(value, 16) for name, value in re.findall(r"\.(\w+)\s*=\s*(0[xX][0-9A-Fa-f]+)", text)}


def read_installer(path):
    names = {"PMAP_PROTECT", "PMAP_PROTECT_P", "PMAP_STORE"} | {name for name, _ in PATCHES}
    table = {}

    for version, name, value in re.findall(r"#define\s+K(\d+)_(\w+)\s+(0[xX][0-9A-Fa-f]+)", path.read_text()):
        if name in names:
            table[(int(version), name)] = int(value, 16)

    return table


def need(values, name, version):
    if name not in values:
        fail(f"{version}: {name} is missing from the ps4-hen sources")

    return values[name]


def hexv(value):
    return f"0x{value:x}"


def firmware_entry(version, offsets, installer, symbols):
    def installer_value(name):
        key = (version, name)

        if key not in installer:
            fail(f"{version}: K{version}_{name} is missing from installer/include/offsets.h")

        return installer[key]

    lines = [f"{{{version},", f" {hexv(installer_value('PMAP_PROTECT'))},", f" {hexv(installer_value('PMAP_PROTECT_P'))},", f" {hexv(installer_value('PMAP_STORE'))},", " {"]

    for name in symbols:
        lines.append(f"     .{name} = {hexv(need(offsets, name, version))},")

    lines.append(" },")

    calls = [f"{{{hexv(need(offsets, hook, version))}, {hexv(need(offsets, target, version))}}}" for hook, target in CALLS]

    lines.append(" {" + ",\n  ".join(calls) + "},")

    patches = [f"{{{hexv(installer_value(name))}, {{{data}}}}}" for name, data in PATCHES]

    lines.append(" {" + ",\n  ".join(patches) + "},")

    shellcore = ", ".join(hexv(need(offsets, name, version)) for name in SHELLCORE)

    lines.append(" {" + shellcore + "}},")

    return "\n".join(lines)


def remote_play_entry(version, offsets):
    values = ", ".join(hexv(need(offsets, name, version)) for name in REMOTE_PLAY)

    return f"{{{version}, {values}}},"


def main():
    if len(sys.argv) != 2:
        fail("usage: generate.py <ps4-hen checkout>")

    hen = Path(sys.argv[1])
    sources = sorted((hen / "kpayload" / "source" / "offsets").glob("*.c"), key=lambda p: int(p.stem))

    if not sources:
        fail(f"no offset files under {hen}/kpayload/source/offsets")

    installer = read_installer(hen / "installer" / "include" / "offsets.h")
    symbols = symbol_names()
    firmware, remote_play = [], []

    for source in sources:
        version = int(source.stem)
        offsets = read_offsets(source)

        firmware.append(firmware_entry(version, offsets, installer, symbols))
        remote_play.append(remote_play_entry(version, offsets))

    for name, rows in (("firmware_table.inc", firmware), ("remoteplay_table.inc", remote_play)):
        with open(ROOT / "source" / name, "w", newline="\n") as out:
            out.write("\n".join(rows) + "\n")

    print(f"{len(sources)} firmwares: {sources[0].stem} to {sources[-1].stem}")


main()
