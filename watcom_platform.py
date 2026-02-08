"""Binary Ninja platform registration for Watcom MS-DOS 32-bit binaries."""

from __future__ import annotations

import struct
from typing import Optional, Tuple

from binaryninja import (
    Architecture,
    BinaryView,
    BinaryViewType,
    CallingConvention,
    Endianness,
    Platform,
    log_error,
    log_info,
    log_warn,
)

PLATFORM_NAME = "watcom-dos32-x86"
OS_NAME = "watcom-dos"
REGPARM_NAME = "regparm"

_INITIALIZED = False


class WatcomDos32Platform(Platform):
    name = PLATFORM_NAME


class WatcomRegparmCallingConvention(CallingConvention):
    """Fallback regparm convention when x86 does not already provide one."""

    caller_saved_regs = ["eax", "ecx", "edx"]
    callee_saved_regs = ["ebx", "esi", "edi", "ebp"]
    int_arg_regs = ["eax", "edx", "ecx"]
    int_return_reg = "eax"
    high_int_return_reg = "edx"
    stack_adjusted_on_return = False


def _read_u32_le(data: bytes, offset: int) -> Optional[int]:
    if len(data) < offset + 4:
        return None
    return struct.unpack_from("<I", data, offset)[0]


def _is_watcom_dos32(view: BinaryView) -> bool:
    mz_header = view.read(0, 0x40)
    if len(mz_header) < 0x40 or mz_header[:2] != b"MZ":
        return False

    new_header_offset = _read_u32_le(mz_header, 0x3C)
    if new_header_offset is None or new_header_offset == 0:
        return False

    new_header_sig = view.read(new_header_offset, 2)
    return new_header_sig in (b"LE", b"LX")


def _get_or_create_platform(arch: Architecture) -> Tuple[Platform, bool]:
    platform = Platform.get(PLATFORM_NAME)
    if platform is not None:
        return platform, False

    platform = WatcomDos32Platform(arch)
    platform.register(OS_NAME)
    return platform, True


def _find_or_create_regparm(arch: Architecture) -> CallingConvention:
    for name, calling_convention in arch.calling_conventions.items():
        if name.lower() == REGPARM_NAME:
            return calling_convention

    regparm = WatcomRegparmCallingConvention(arch, REGPARM_NAME)
    arch.register_calling_convention(regparm)
    return regparm


def _ensure_platform_calling_convention(platform: Platform, regparm: CallingConvention) -> None:
    if all(existing.name != regparm.name for existing in platform.calling_conventions):
        platform.register_calling_convention(regparm)
    platform.default_calling_convention = regparm


def _register_platform_recognizer(view_name: str, platform: Platform) -> None:
    view_type = BinaryViewType.get(view_name)
    if view_type is None:
        return

    def _recognize_watcom_dos32(view: BinaryView, metadata) -> Optional[Platform]:
        del metadata
        if _is_watcom_dos32(view):
            return platform
        return None

    view_type.register_platform_recognizer(0, Endianness.LittleEndian, _recognize_watcom_dos32)


def register_watcom_dos32_platform() -> None:
    global _INITIALIZED

    if _INITIALIZED:
        return

    try:
        arch = Architecture["x86"]
        platform, created = _get_or_create_platform(arch)
        regparm = _find_or_create_regparm(arch)
        _ensure_platform_calling_convention(platform, regparm)

        if created:
            _register_platform_recognizer("Raw", platform)
            _register_platform_recognizer("Mapped", platform)

        log_info(
            f"Registered {platform.name} for Watcom DOS32 with default calling convention '{regparm.name}'."
        )
    except KeyError:
        log_warn("x86 architecture is unavailable; Watcom DOS32 platform was not registered.")
    except Exception as exc:  # pragma: no cover
        log_error(f"Failed to register Watcom DOS32 platform: {exc}")
    finally:
        _INITIALIZED = True
