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
    values = {}

    for name, value in re.findall(r"\.(\w+)\s*=\s*(0[xX][0-9A-Fa-f]+)", text):
        if name in values:
            fail(f"{path.name}: duplicate offset {name}")

        values[name] = int(value, 16)

    return values


def read_installer(path):
    names = {"PMAP_PROTECT", "PMAP_PROTECT_P", "PMAP_STORE"} | {name for name, _ in PATCHES}
    table = {}

    for version, name, value in re.findall(r"#define\s+K(\d+)_(\w+)\s+(0[xX][0-9A-Fa-f]+)", path.read_text()):
        if name in names:
            key = (int(version), name)

            if key in table:
                fail(f"{path.name}: duplicate K{version}_{name}")

            table[key] = int(value, 16)

    return table


def condition_matches(condition, version):
    values = re.fullmatch(r"fw_version\s*==\s*\d+(?:\s*\|\|\s*fw_version\s*==\s*\d+)*", condition)

    if values:
        versions = [int(value) for value in re.findall(r"fw_version\s*==\s*(\d+)", condition)]
        return version in versions

    range_match = re.fullmatch(r"fw_version\s*>=\s*(\d+)\s*&&\s*fw_version\s*<=\s*(\d+)", condition)

    if range_match:
        return int(range_match.group(1)) <= version <= int(range_match.group(2))

    minimum = re.fullmatch(r"fw_version\s*>=\s*(\d+)", condition)

    if minimum:
        return version >= int(minimum.group(1))

    maximum = re.fullmatch(r"fw_version\s*<=\s*(\d+)", condition)

    if maximum:
        return version <= int(maximum.group(1))

    fail(f"unsupported exploit_fixes() condition: {condition}")


def exploit_fix_patches(lines, version):
    patches = []
    address = None
    values = {}
    active = []
    write_count = 0

    def flush():
        nonlocal address, values

        if address is None or not values:
            address, values = None, {}
            return

        indexes = sorted(values)
        start = previous = indexes[0]
        run = [values[start]]

        for index in indexes[1:]:
            if index != previous + 1:
                patches.append((address + start, run))
                start, run = index, []

            run.append(values[index])
            previous = index

        patches.append((address + start, run))
        address, values = None, {}

    for line in lines:
        code = line.split("//", 1)[0].strip()

        if not code:
            continue

        if "kmem" in code and not (
            re.match(r"uint8_t\s*\*\s*kmem\s*;", code)
            or re.match(r"kmem\s*=\s*\(uint8_t\s*\*\)&kernel_ptr\[0x[0-9A-Fa-f]+\]\s*;", code)
            or re.match(r"kmem\[[^]]+\]\s*=\s*[^;]+;", code)
        ):
            fail(f"{version}: unsupported exploit patch expression {code}")

        if "kernel_ptr[" in code and "kmem" not in code and "&kernel_ptr[" not in code:
            fail(f"{version}: unsupported direct kernel write {code}")

        nested = re.match(r"if\s*\((fw_version[^)]*)\)\s*\{", code)

        if nested:
            active.append((active[-1] if active else True) and condition_matches(nested.group(1), version))
            continue

        if not active or active[-1]:
            target = re.search(r"kmem\s*=\s*\(uint8_t\s*\*\)&kernel_ptr\[(0x[0-9A-Fa-f]+)\]", code)

            if target:
                flush()
                address = int(target.group(1), 16)
            else:
                value = re.search(r"kmem\[([^]]+)\]\s*=\s*([^;]+);", code)

                if value:
                    if address is None:
                        fail(f"{version}: exploit patch bytes have no kernel offset")

                    try:
                        index = int(value.group(1), 0)
                        byte = int(value.group(2), 0)
                    except ValueError:
                        fail(f"{version}: unsupported exploit patch write {code}")

                    values[index] = byte
                    write_count += 1
                elif "kmem[" in code and "=" in code:
                    fail(f"{version}: unsupported exploit patch write {code}")

        if code.startswith("}") and active:
            active.pop()

    flush()

    for offset, data in patches:
        if not data or len(data) > 16 or any(value < 0 or value > 255 for value in data):
            fail(f"{version}: invalid exploit patch at {hexv(offset)}")

    if not write_count:
        fail(f"{version}: no exploit patch writes were imported")

    return patches


def read_exploit_fixes(path, versions):
    text = path.read_text()
    start = text.find("static int kpayload_exploit_fixes")
    end = text.find("// Passes on the result of kpayload_patches", start)

    if start < 0 or end < 0:
        fail("installer/source/kpayloads.c does not contain exploit_fixes()")

    lines = text[start:end].splitlines()
    branches = []

    for index, line in enumerate(lines):
        branch = re.search(r"(?:^|\})\s*(?:if|else if)\s*\((fw_version[^)]*)\)\s*\{", line)

        if branch:
            branches.append((index, branch.group(1)))

    if not branches:
        fail("exploit_fixes() contains no firmware-specific patch blocks")

    def is_write(line):
        code = line.split("//", 1)[0].strip()
        return bool(re.match(r"kmem\s*=", code) or re.match(r"kmem\s*\[[^]]+\]\s*=", code))

    total_writes = sum(is_write(line) for line in lines)
    block_writes = 0

    for index, (line_index, _) in enumerate(branches):
        next_index = branches[index + 1][0] if index + 1 < len(branches) else len(lines)
        block_writes += sum(is_write(line) for line in lines[line_index + 1:next_index])

    if total_writes != block_writes:
        fail("exploit_fixes() has patch writes outside recognized firmware blocks")

    table = {}

    for branch_index, (line_index, condition) in enumerate(branches):
        next_index = branches[branch_index + 1][0] if branch_index + 1 < len(branches) else len(lines)
        body = lines[line_index + 1:next_index]

        for version in sorted(versions):
            if not condition_matches(condition, version):
                continue

            patches = exploit_fix_patches(body, version)

            if version in table:
                fail(f"{version}: duplicate exploit_fixes() firmware block")

            table[version] = patches

    # No matching branch means ps4-hen has no exploit_fixes() writes for this
    # firmware. Keep it in the generated table as an explicitly supported empty set.
    for version in versions - table.keys():
        table[version] = []

    return table


def write_exploit_fixes(path, table):
    lines = ["/* Generated from ps4-hen installer/source/kpayloads.c. */", ""]

    for version, patches in sorted(table.items()):
        if not patches:
            continue

        lines.append(f"static const struct kstuff_exploit_patch exploit_fixes_{version}[] = {{")

        for offset, data in patches:
            bytes_text = ", ".join(hex(value) for value in data)
            lines.append(f"    {{{hex(offset)}, {len(data)}, {{{bytes_text}}}}},")

        lines.append("};")
        lines.append("")

    lines.append("#define EXPLOIT_FIX_SET_LIST \\")

    for index, version in enumerate(sorted(table)):
        suffix = " \\" if index + 1 < len(table) else ""
        if table[version]:
            entry = f"{{{version}, exploit_fixes_{version}, sizeof(exploit_fixes_{version}) / sizeof(exploit_fixes_{version}[0])}}"
        else:
            entry = f"{{{version}, nullptr, 0}}"

        lines.append(f"    {entry}," + suffix)

    with open(path, "w", newline="\n") as out:
        out.write("\n".join(lines) + "\n")


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
    if len(sys.argv) not in (2, 3):
        fail("usage: generate.py <ps4-hen checkout> [output directory]")

    hen = Path(sys.argv[1])
    output = Path(sys.argv[2]) if len(sys.argv) == 3 else ROOT
    offset_dir = hen / "kpayload" / "source" / "offsets"
    source_paths = list(offset_dir.glob("*.c"))

    try:
        sources = sorted(source_paths, key=lambda p: int(p.stem))
    except ValueError as error:
        fail(f"firmware offset filename is not numeric: {error}")

    if not sources:
        fail(f"no offset files under {hen}/kpayload/source/offsets")

    versions = [int(source.stem) for source in sources]

    if len(set(versions)) != len(versions):
        fail("duplicate firmware offset files")

    installer = read_installer(hen / "installer" / "include" / "offsets.h")
    symbols = symbol_names()
    firmware, remote_play = [], []

    for source in sources:
        version = int(source.stem)
        offsets = read_offsets(source)

        firmware.append(firmware_entry(version, offsets, installer, symbols))
        remote_play.append(remote_play_entry(version, offsets))

    exploit_fixes = read_exploit_fixes(hen / "installer" / "source" / "kpayloads.c", set(versions))

    for name, rows in (("firmware_table.inc", firmware), ("remoteplay_table.inc", remote_play)):
        with open(output / "source" / name, "w", newline="\n") as out:
            out.write("\n".join(rows) + "\n")

    write_exploit_fixes(output / "source" / "exploit_fixes_table.inc", exploit_fixes)

    print(f"{len(sources)} firmwares: {sources[0].stem} to {sources[-1].stem}")


main()
