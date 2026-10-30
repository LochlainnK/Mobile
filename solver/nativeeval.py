"""Emulate a JNI native function from a challenge's bundled .so.

Some v2 "analysis" variants route the token through a `native` method whose
body lives in `lib/<abi>/lib*.so` (x86_64 ELF).  These are small leaf functions
(``jlong f(JNIEnv*, jclass, jlong)`` doing pure register arithmetic), so we map
the library's PT_LOAD segments into a Unicorn x86-64 VM, put the argument in the
System V register, run to return, and read ``rax``.  No syscalls or external
calls are involved, so emulation is safe and deterministic.

Requires unicorn and pyelftools.
"""

import io

MASK64 = (1 << 64) - 1
PAGE = 0x1000


def _sym_vaddr(elf, symbol):
    for secname in (".dynsym", ".symtab"):
        sec = elf.get_section_by_name(secname)
        if not sec:
            continue
        for sym in sec.iter_symbols():
            if sym.name == symbol:
                return sym["st_value"]
    return None


def jni_symbol(class_token, method):
    """Build the JNI export name for a (possibly overloaded-free) method."""
    inner = class_token.strip()
    if inner.startswith("L") and inner.endswith(";"):
        inner = inner[1:-1]
    return "Java_" + inner.replace("/", "_") + "_" + method


def emulate(so_bytes, symbol, args):
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_64
    from unicorn.x86_const import (
        UC_X86_REG_RSP, UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX,
        UC_X86_REG_RCX, UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_RAX,
    )
    from elftools.elf.elffile import ELFFile

    elf = ELFFile(io.BytesIO(so_bytes))
    vaddr = _sym_vaddr(elf, symbol)
    if vaddr is None:
        raise KeyError("symbol not found: %s" % symbol)

    loads = [s for s in elf.iter_segments() if s["p_type"] == "PT_LOAD"]
    lo = min(s["p_vaddr"] for s in loads) & ~(PAGE - 1)
    hi = max(s["p_vaddr"] + s["p_memsz"] for s in loads)
    hi = (hi + PAGE - 1) & ~(PAGE - 1)

    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(lo, hi - lo)
    for s in loads:
        uc.mem_write(s["p_vaddr"], s.data())

    stack_base, stack_sz = 0x7F000000, 0x100000
    uc.mem_map(stack_base, stack_sz)
    ret_addr = 0x5F000000
    uc.mem_map(ret_addr, PAGE)
    rsp = stack_base + stack_sz // 2
    rsp -= 8
    uc.mem_write(rsp, ret_addr.to_bytes(8, "little"))

    uc.reg_write(UC_X86_REG_RSP, rsp)
    uc.reg_write(UC_X86_REG_RDI, 0)   # JNIEnv*
    uc.reg_write(UC_X86_REG_RSI, 0)   # jclass / this
    argregs = [UC_X86_REG_RDX, UC_X86_REG_RCX, UC_X86_REG_R8, UC_X86_REG_R9]
    for i, a in enumerate(args[:4]):
        uc.reg_write(argregs[i], a & MASK64)

    uc.emu_start(vaddr, ret_addr, timeout=0, count=100000)
    return uc.reg_read(UC_X86_REG_RAX) & MASK64
