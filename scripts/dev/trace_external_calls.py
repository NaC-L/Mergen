#!/usr/bin/env python3
"""Emulate a PE binary and report where it issues external (IAT) calls.

Diagnostic tool, not a regression check. Use it to answer one question on a
specific lift target: "what x86 instruction in this binary issues the call to
this external function, and through what addressing form?"

Approach:
- Parse the PE, walk the import directory, and patch every IAT slot with a
  unique sentinel address (in an *unmapped* high page).
- Map all PE sections into Unicorn at their virtual addresses.
- Allocate a stack and a TEB so GS-relative reads behave.
- Hook every code instruction; when the upcoming `call`/`jmp` resolves to a
  sentinel address, log the call-site (the instruction's own VA) plus the
  addressing form (direct / register / memory operand) and the import name.
- Stop after the first N sentinel hits or after `--max-insns` instructions
  total (default 1,000,000).

This sees the *real* call mechanism the binary uses at runtime, regardless of
how the lifter chooses to model it. Compare against what the lifter emits in
`output_no_opts.ll` to localise where the lifter's import-resolution path
either misses the callsite entirely or fails to recognise the addressing form.
"""
from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    import capstone
    from capstone import x86 as cs_x86
    import unicorn
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_64
    from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED, UC_HOOK_INSN_INVALID
    from unicorn import UC_HOOK_MEM_WRITE
    from unicorn import x86_const as ux
except ImportError as exc:
    sys.exit(f"Missing dependency: {exc}. pip install unicorn capstone")


# Map capstone X86 register ids -> Unicorn register ids by name.
def _build_reg_translation(md: capstone.Cs) -> Dict[int, int]:
    name_to_uc = {
        attr.removeprefix("UC_X86_REG_").lower(): getattr(ux, attr)
        for attr in dir(ux)
        if attr.startswith("UC_X86_REG_") and attr != "UC_X86_REG_INVALID"
    }
    out: Dict[int, int] = {}
    for cs_id in range(1, cs_x86.X86_REG_ENDING):
        try:
            name = md.reg_name(cs_id)
        except Exception:
            continue
        if not name:
            continue
        uc_id = name_to_uc.get(name.lower())
        if uc_id is not None:
            out[cs_id] = uc_id
    return out


# ---------------------------------------------------------------------------
# PE parsing — minimal, just enough to find sections and the import table.
# ---------------------------------------------------------------------------


def _parse_pe(data: bytes) -> dict:
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_off : pe_off + 4] != b"PE\x00\x00":
        raise SystemExit("Not a PE file")
    nsec = struct.unpack_from("<H", data, pe_off + 6)[0]
    sopt = struct.unpack_from("<H", data, pe_off + 20)[0]
    opt = pe_off + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic != 0x20B:
        raise SystemExit("PE32+ (x86_64) only")
    image_base = struct.unpack_from("<Q", data, opt + 24)[0]
    image_size = struct.unpack_from("<I", data, opt + 56)[0]
    ddir_off = opt + 112  # IMAGE_OPTIONAL_HEADER64.DataDirectory
    imp_rva = struct.unpack_from("<I", data, ddir_off + 1 * 8)[0]
    imp_size = struct.unpack_from("<I", data, ddir_off + 1 * 8 + 4)[0]

    sec_table = opt + sopt
    sections: List[Tuple[str, int, int, int, int]] = []
    for i in range(nsec):
        off = sec_table + i * 40
        name = data[off : off + 8].rstrip(b"\0").decode("ascii", "replace")
        vsz = struct.unpack_from("<I", data, off + 8)[0]
        va = struct.unpack_from("<I", data, off + 12)[0]
        rsz = struct.unpack_from("<I", data, off + 16)[0]
        roff = struct.unpack_from("<I", data, off + 20)[0]
        sections.append((name, va, vsz, roff, rsz))

    return {
        "image_base": image_base,
        "image_size": image_size,
        "sections": sections,
        "import_rva": imp_rva,
        "import_size": imp_size,
    }


def _rva_to_off(sections, rva: int) -> Optional[int]:
    for _name, va, vsz, roff, rsz in sections:
        if va <= rva < va + max(vsz, rsz):
            return roff + (rva - va)
    return None


def _parse_imports(data: bytes, info: dict) -> List[Tuple[int, str]]:
    """Return [(iat_slot_va, function_name)] across every imported DLL."""
    if info["import_rva"] == 0:
        return []
    base = info["image_base"]
    secs = info["sections"]
    desc = _rva_to_off(secs, info["import_rva"])
    out: List[Tuple[int, str]] = []
    while True:
        ilt_rva = struct.unpack_from("<I", data, desc)[0]
        name_rva = struct.unpack_from("<I", data, desc + 12)[0]
        iat_rva = struct.unpack_from("<I", data, desc + 16)[0]
        if ilt_rva == 0 and iat_rva == 0:
            break
        dll_off = _rva_to_off(secs, name_rva)
        dll = data[dll_off:].split(b"\0", 1)[0].decode("ascii", "replace")
        thunks_rva = ilt_rva or iat_rva
        thunks_off = _rva_to_off(secs, thunks_rva)
        if thunks_off is None:
            desc += 20
            continue
        idx = 0
        while True:
            entry = struct.unpack_from("<Q", data, thunks_off + idx * 8)[0]
            if entry == 0:
                break
            iat_slot_va = base + iat_rva + idx * 8
            if entry & (1 << 63):
                ordinal = entry & 0xFFFF
                fname = f"{dll}#{ordinal}"
            else:
                hint_off = _rva_to_off(secs, entry & 0x7FFFFFFF)
                fname = data[hint_off + 2 :].split(b"\0", 1)[0].decode("ascii", "replace")
            out.append((iat_slot_va, fname))
            idx += 1
        desc += 20
    return out


# ---------------------------------------------------------------------------
# Operand resolution (capstone -> effective address)
# ---------------------------------------------------------------------------


def _compute_ea(uc: Uc, ins, op, reg_xlat: Dict[int, int]) -> Optional[int]:
    mem = op.mem
    base_v = 0
    if mem.base:
        if mem.base == cs_x86.X86_REG_RIP:
            base_v = ins.address + ins.size
        else:
            uc_id = reg_xlat.get(mem.base)
            if uc_id is None:
                return None
            base_v = uc.reg_read(uc_id)
    index_v = 0
    if mem.index:
        uc_id = reg_xlat.get(mem.index)
        if uc_id is None:
            return None
        index_v = uc.reg_read(uc_id)
    return (base_v + index_v * mem.scale + mem.disp) & 0xFFFFFFFFFFFFFFFF


# ---------------------------------------------------------------------------
# Main tracer
# ---------------------------------------------------------------------------


SENTINEL_BASE = 0xDEAD_0000  # picked so it sits well outside any mapped region
STACK_BASE = 0x7FFE_0000_0000
STACK_SIZE = 0x100_0000
TEB_BASE = 0x7FFD_0000_0000
TEB_SIZE = 0x10000


def trace(
    binary: Path,
    entry: int,
    *,
    max_insns: int,
    max_hits: int,
    verbose_calls: bool,
    dump_visited: Optional[Path] = None,
) -> int:
    data = binary.read_bytes()
    info = _parse_pe(data)
    imports = _parse_imports(data, info)
    base = info["image_base"]

    print(f"[pe] image_base=0x{base:x} image_size=0x{info['image_size']:x}")
    print(f"[pe] {len(imports)} imports across {len({n.split('#')[0] for _, n in imports})} DLLs")
    for iat, name in imports[:8]:
        print(f"     IAT[0x{iat:x}] -> {name}")
    if len(imports) > 8:
        print(f"     ... +{len(imports) - 8} more")

    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    reg_xlat = _build_reg_translation(md)

    # Map the full image (page-aligned) and write each section's raw bytes.
    page = 0x1000
    img_size = (info["image_size"] + page - 1) & ~(page - 1)
    uc.mem_map(base, img_size, unicorn.UC_PROT_ALL)
    for name, va, _vsz, roff, rsz in info["sections"]:
        if rsz:
            uc.mem_write(base + va, data[roff : roff + rsz])

    # Stack
    uc.mem_map(STACK_BASE, STACK_SIZE, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)
    rsp_top = STACK_BASE + STACK_SIZE - 0x1000
    # TEB at GS_BASE, with sane StackBase / StackLimit
    uc.mem_map(TEB_BASE, TEB_SIZE, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)
    uc.mem_write(TEB_BASE + 0x08, struct.pack("<Q", STACK_BASE + STACK_SIZE))
    uc.mem_write(TEB_BASE + 0x10, struct.pack("<Q", STACK_BASE))
    uc.reg_write(ux.UC_X86_REG_MSR, (0xC0000101, TEB_BASE))  # IA32_GS_BASE

    # Map a page of `ret` instructions at the sentinel base so each import
    # sentinel address is a mapped minimal stub that immediately returns to
    # its caller (the VM's pre-staged continuation). This lets the
    # emulator continue past the first import and observe subsequent ones.
    SENTINEL_PAGE_SIZE = 0x10000
    uc.mem_map(SENTINEL_BASE, SENTINEL_PAGE_SIZE, unicorn.UC_PROT_READ | unicorn.UC_PROT_EXEC)
    # Fill with 0xC3 (near ret) so any fetch within the page just rets.
    uc.mem_write(SENTINEL_BASE, b"\xC3" * SENTINEL_PAGE_SIZE)
    # Patch IAT: every slot points at a unique sentinel that now executes
    # as a ret. The code_hook below uses sentinel_to_name to label calls.
    sentinel_to_name: Dict[int, str] = {}
    for i, (iat_va, fname) in enumerate(imports):
        sentinel = SENTINEL_BASE + i * 0x10
        uc.mem_write(iat_va, struct.pack("<Q", sentinel))
        sentinel_to_name[sentinel] = fname

    # Initial state
    for r in (
        ux.UC_X86_REG_RAX, ux.UC_X86_REG_RBX, ux.UC_X86_REG_RCX, ux.UC_X86_REG_RDX,
        ux.UC_X86_REG_RSI, ux.UC_X86_REG_RDI, ux.UC_X86_REG_RBP,
        ux.UC_X86_REG_R8, ux.UC_X86_REG_R9, ux.UC_X86_REG_R10, ux.UC_X86_REG_R11,
        ux.UC_X86_REG_R12, ux.UC_X86_REG_R13, ux.UC_X86_REG_R14, ux.UC_X86_REG_R15,
    ):
        uc.reg_write(r, 0)
    sentinel_ret = 0xC0DE_0000
    uc.mem_write(rsp_top - 8, struct.pack("<Q", sentinel_ret))
    uc.reg_write(ux.UC_X86_REG_RSP, rsp_top - 8)

    # State the hooks share via closure
    state = {
        "insns": 0,
        "hits": [],         # [(callsite, mnemonic, kind, target, name)]
        "last_pc": entry,
    }

    # Ordered list of unique instruction PCs (each address recorded once, in
    # the order the emulator first executes it). Useful for diffing against
    # the lifter's reached-addresses list to find the divergence point.
    visited_pcs: List[int] = []
    visited_set: set = set()

    # Every time a stack write stores a sentinel value, record
    # (sentinel, writer_pc, stack_addr, insn_count). Themida obfuscates with
    # push-pop swap gadgets so a single sentinel may be staged transiently
    # multiple times before the final ret picks it up.
    sentinel_pushes: List[Tuple[int, int, int, int]] = []

    def code_hook(_uc, addr, size, _ud):
        state["insns"] += 1
        state["last_pc"] = addr
        if addr not in visited_set:
            visited_set.add(addr)
            visited_pcs.append(addr)
        if state["insns"] > max_insns:
            uc.emu_stop()
            return
        try:
            buf = bytes(uc.mem_read(addr, size))
        except Exception:
            return
        for ins in md.disasm(buf, addr):
            mn = ins.mnemonic
            is_ret = mn in ("ret", "retf", "iret", "iretq", "retq")
            is_transfer = is_ret or mn in ("call", "jmp")
            if not is_transfer:
                break
            target: Optional[int] = None
            kind = "?"
            if is_ret:
                # The target is [rsp]: the value about to be popped into RIP.
                rsp_now = uc.reg_read(ux.UC_X86_REG_RSP)
                try:
                    target = struct.unpack("<Q", bytes(uc.mem_read(rsp_now, 8)))[0]
                    kind = f"pop[rsp=0x{rsp_now:x}]"
                except Exception:
                    kind = f"pop[rsp=0x{rsp_now:x}]-unread"
            elif ins.operands:
                op = ins.operands[0]
                if op.type == cs_x86.X86_OP_IMM:
                    target = op.imm
                    kind = "imm"
                elif op.type == cs_x86.X86_OP_REG:
                    uc_id = reg_xlat.get(op.reg)
                    if uc_id is not None:
                        target = uc.reg_read(uc_id)
                        kind = f"reg:{md.reg_name(op.reg)}"
                elif op.type == cs_x86.X86_OP_MEM:
                    ea = _compute_ea(uc, ins, op, reg_xlat)
                    if ea is not None:
                        try:
                            target = struct.unpack("<Q", bytes(uc.mem_read(ea, 8)))[0]
                            kind = f"mem@0x{ea:x}"
                        except Exception:
                            kind = f"mem@0x{ea:x}-unread"
            if target is None:
                break
            name = sentinel_to_name.get(target)
            external = name is not None or not (base <= target < base + info["image_size"])
            if verbose_calls or external:
                tag = "[HIT ]" if name else ("[EXT?]" if external else "[xfer]")
                resolved = name if name else ("<unknown-extern>" if external else "<internal>")
                print(
                    f"{tag} insn={state['insns']:>7} @0x{addr:x} "
                    f"{mn} {ins.op_str} | kind={kind} target=0x{target:x} -> {resolved}"
                )
                if name:
                    state["hits"].append((addr, mn, kind, target, name))
                    if len(state["hits"]) >= max_hits:
                        uc.emu_stop()
            break

    def unmapped_hook(_uc, _access, addr, _size, _value, _ud):
        # Catches both data accesses and instruction fetches into unmapped space.
        # Sentinel fetches are interesting; everything else is usually a real
        # bug in the emulator setup we want to surface.
        name = sentinel_to_name.get(addr)
        rsp_now = uc.reg_read(ux.UC_X86_REG_RSP)
        try:
            ret_to = struct.unpack("<Q", bytes(uc.mem_read(rsp_now, 8)))[0]
        except Exception:
            ret_to = 0
        if name:
            print(
                f"[FETCH-SENTINEL] -> {name}  insn={state['insns']}  "
                f"last_pc=0x{state['last_pc']:x}  rsp=0x{rsp_now:x}  ret_to=0x{ret_to:x}"
            )
            # Simulate the import returning: set RIP=ret_to, bump rsp
            # (the original ret already popped, so just jump to the saved
            # return address). Also stash a fake return in RAX so callers
            # don't blow up on checks.
            try:
                uc.reg_write(ux.UC_X86_REG_RIP, ret_to)
                uc.reg_write(ux.UC_X86_REG_RAX, 0x1234)
                return True  # handled; continue execution
            except Exception as exc:
                print(f"  [!] failed to redirect: {exc}")
                return False
        print(
            f"[UNMAPPED] addr=0x{addr:x}  insn={state['insns']}  "
            f"last_pc=0x{state['last_pc']:x}  rsp=0x{rsp_now:x}  ret_to=0x{ret_to:x}"
        )
        return False  # let unicorn raise; we'll handle in the outer try

    uc.hook_add(UC_HOOK_CODE, code_hook)
    uc.hook_add(UC_HOOK_MEM_UNMAPPED, unmapped_hook)

    def mem_write_hook(_uc, _access, addr, size, value, _ud):
        if size != 8:
            return
        if not (STACK_BASE <= addr < STACK_BASE + STACK_SIZE):
            return
        uv = value & 0xFFFFFFFFFFFFFFFF
        if uv in sentinel_to_name:
            sentinel_pushes.append((uv, state["last_pc"], addr, state["insns"]))

    uc.hook_add(UC_HOOK_MEM_WRITE, mem_write_hook)

    print(f"\n[run] starting emulation @ 0x{entry:x}, max_insns={max_insns}\n")
    try:
        uc.emu_start(entry, 0, count=max_insns)
    except unicorn.UcError as exc:
        rip = uc.reg_read(ux.UC_X86_REG_RIP)
        print(f"\n[stop] unicorn raised at RIP=0x{rip:x} after {state['insns']} insns: {exc}")
    else:
        print(f"\n[stop] emulation ended cleanly after {state['insns']} insns")

    print(f"\n--- summary ---")
    print(f"instructions executed : {state['insns']}")
    print(f"sentinel hits         : {len(state['hits'])}")
    for callsite, mn, kind, target, name in state["hits"]:
        print(f"  @0x{callsite:x}  {mn:<4}  kind={kind:<24}  -> {name}")
    if sentinel_pushes:
        print(f"\n--- sentinel push history ({len(sentinel_pushes)} stack writes) ---")
        from collections import defaultdict
        per_sent: Dict[int, List[Tuple[int, int, int]]] = defaultdict(list)
        for s, pc, a, n in sentinel_pushes:
            per_sent[s].append((pc, a, n))
        for sent, events in per_sent.items():
            name = sentinel_to_name[sent]
            print(f"  {name}: {len(events)} pushes; last 5:")
            for pc, a, n in events[-5:]:
                print(f"      insn={n:>7} @0x{pc:x} -> [0x{a:x}]")
    if dump_visited is not None:
        dump_visited.write_text(
            "\n".join(f"0x{a:x}" for a in visited_pcs) + "\n",
            encoding="utf-8",
        )
        print(f"dumped {len(visited_pcs)} unique PCs to {dump_visited}")
    return 0 if state["hits"] else 1


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("binary", type=Path)
    ap.add_argument("entry", help="entry VA, e.g. 0x140001000")
    ap.add_argument("--max-insns", type=int, default=1_000_000)
    ap.add_argument("--max-hits", type=int, default=8,
                    help="stop after this many distinct external-call observations")
    ap.add_argument("--verbose-calls", action="store_true",
                    help="log every call/jmp, not just the external ones")
    ap.add_argument("--dump-visited", type=Path, default=None,
                    help="write newline-separated unique PCs executed, in order")
    args = ap.parse_args()
    sys.exit(trace(
        args.binary,
        int(args.entry, 0),
        max_insns=args.max_insns,
        max_hits=args.max_hits,
        verbose_calls=args.verbose_calls,
        dump_visited=args.dump_visited,
    ))


if __name__ == "__main__":
    main()
