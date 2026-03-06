#!/usr/bin/env python3
"""Sleigh/P-code based oracle provider for Mergen instruction test vectors.

Uses pypcode (Ghidra's SLEIGH engine) to translate x86_64 instructions into
P-code, then concretely emulates the P-code micro-ops to produce expected
register and flag outputs.  This gives a second, independent oracle alongside
Unicorn for cross-validation.

Requirements:
    pip install pypcode
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from pypcode import Context, OpCode

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_CODE_ADDRESS = 0x1000000
DEFAULT_STACK_ADDRESS = 0x2000000
DEFAULT_STACK_SIZE = 0x20000
DEFAULT_CODE_SIZE = 0x1000

class PcodeEmulatorError(RuntimeError):
    pass


@dataclass
class SleighOracleResult:
    registers: Dict[str, int]
    flags: Dict[str, int]


# ---------------------------------------------------------------------------
# Concrete P-code emulator
# ---------------------------------------------------------------------------


class PcodeEmulatorState:
    """Flat byte-addressable storage for register-space, unique-space, and RAM."""

    def __init__(self) -> None:
        # register space: 0x0 .. 0x800 covers x86_64 GPRs, flags, segments, etc.
        self._regs = bytearray(0x1000)
        # unique (temp) space: sparse dict {offset: bytes} to avoid large alloc
        self._unique: Dict[int, bytes] = {}
        # RAM: mapped regions as {base_addr: bytearray}
        self._mem: Dict[int, bytearray] = {}

    # -- memory mapping --

    def map_memory(self, base: int, size: int) -> None:
        self._mem[base] = bytearray(size)

    def _find_region(self, addr: int, size: int) -> Tuple[bytearray, int]:
        for base, region in self._mem.items():
            if base <= addr and addr + size <= base + len(region):
                return region, addr - base
        raise PcodeEmulatorError(
            f"Memory access at {addr:#x} (size {size}) outside mapped regions"
        )

    # -- generic read/write by space name --

    def read(self, space: str, offset: int, size: int) -> int:
        if space == "register":
            data = self._regs[offset : offset + size]
        elif space == "unique":
            data = self._unique.get(offset, b'\x00' * size)
            data = (data + b'\x00' * size)[:size]
        elif space == "ram":
            region, off = self._find_region(offset, size)
            data = region[off : off + size]
        elif space == "const":
            return offset & ((1 << (size * 8)) - 1)
        else:
            raise PcodeEmulatorError(f"Unsupported space '{space}' for read")
        return int.from_bytes(data, "little")

    def write(self, space: str, offset: int, size: int, value: int) -> None:
        mask = (1 << (size * 8)) - 1
        data = (value & mask).to_bytes(size, "little")
        if space == "register":
            self._regs[offset : offset + size] = data
        elif space == "unique":
            self._unique[offset] = data
        elif space == "ram":
            region, off = self._find_region(offset, size)
            region[off : off + size] = data
        else:
            raise PcodeEmulatorError(f"Unsupported space '{space}' for write")

    # -- helpers for reading/writing varnodes --

    def read_varnode(self, vn) -> int:
        return self.read(vn.space.name, vn.offset, vn.size)

    def write_varnode(self, vn, value: int) -> None:
        self.write(vn.space.name, vn.offset, vn.size, value)

    def write_mem(self, addr: int, data: bytes) -> None:
        region, off = self._find_region(addr, len(data))
        region[off : off + len(data)] = data


class PcodeEmulator:
    """Concretely execute a sequence of P-code ops on a PcodeEmulatorState."""

    def __init__(self, state: PcodeEmulatorState) -> None:
        self.state = state
        self._pc = 0

    def execute(self, ops: list) -> None:
        """Execute a list of PcodeOp objects (from a single translated instruction)."""
        self._pc = 0
        max_iters = len(ops) * 20
        iters = 0
        while self._pc < len(ops):
            iters += 1
            if iters > max_iters:
                raise PcodeEmulatorError("P-code execution exceeded max iterations")
            op = ops[self._pc]
            handler = _OP_DISPATCH.get(op.opcode)
            if handler is None:
                raise PcodeEmulatorError(
                    f"Unimplemented P-code opcode: {op.opcode.name}"
                )
            branch = handler(self, op)
            if branch is not None:
                if branch < 0 or branch >= len(ops):
                    break
                self._pc = branch
            else:
                self._pc += 1

    # -- Helpers --

    def _read(self, vn) -> int:
        return self.state.read_varnode(vn)

    def _write(self, vn, value: int) -> None:
        self.state.write_varnode(vn, value)

    def _mask(self, size: int) -> int:
        return (1 << (size * 8)) - 1

    def _sign_extend(self, value: int, size: int) -> int:
        bits = size * 8
        if value & (1 << (bits - 1)):
            return value - (1 << bits)
        return value

    # -- Opcode implementations --

    def _op_imark(self, op) -> None:
        pass  # Instruction marker, no-op

    def _op_copy(self, op) -> None:
        self._write(op.output, self._read(op.inputs[0]))

    def _op_load(self, op) -> None:
        # LOAD [space_id] addr -> output
        addr = self._read(op.inputs[1])
        space = op.inputs[0].getSpaceFromConst()
        val = self.state.read(space.name, addr, op.output.size)
        self._write(op.output, val)


    def _op_store_fixed(self, op) -> None:
        # STORE has no output; size comes from the value input
        addr = self._read(op.inputs[1])
        value = self._read(op.inputs[2])
        space = op.inputs[0].getSpaceFromConst()
        self.state.write(space.name, addr, op.inputs[2].size, value)

    def _op_branch(self, op) -> Optional[int]:
        target = op.inputs[0]
        if target.space.name == "const":
            # Intra-instruction: const offset is RELATIVE to current PC.
            # Verified empirically against BSF P-code which uses a 3-branch
            # loop (CBRANCH +7, CBRANCH +3, BRANCH -5).  Absolute interpretation
            # produces nonsensical targets; relative yields correct loop control.
            raw = target.offset
            if raw > 0x7FFFFFFF:  # handle negative as signed 32-bit
                raw -= 0x100000000
            return self._pc + raw
        # Inter-instruction branch (ram space) = end of this instruction
        return -1

    def _op_cbranch(self, op) -> Optional[int]:
        cond = self._read(op.inputs[1])
        if cond & 1:
            target = op.inputs[0]
            if target.space.name == "const":
                raw = target.offset
                if raw > 0x7FFFFFFF:
                    raw -= 0x100000000
                return self._pc + raw
            return -1  # inter-instruction
        return None

    # -- Integer arithmetic --

    def _op_int_equal(self, op) -> None:
        a, b = self._read(op.inputs[0]), self._read(op.inputs[1])
        self._write(op.output, 1 if a == b else 0)

    def _op_int_notequal(self, op) -> None:
        a, b = self._read(op.inputs[0]), self._read(op.inputs[1])
        self._write(op.output, 1 if a != b else 0)

    def _op_int_sless(self, op) -> None:
        size = op.inputs[0].size
        a = self._sign_extend(self._read(op.inputs[0]), size)
        b = self._sign_extend(self._read(op.inputs[1]), size)
        self._write(op.output, 1 if a < b else 0)

    def _op_int_slessequal(self, op) -> None:
        size = op.inputs[0].size
        a = self._sign_extend(self._read(op.inputs[0]), size)
        b = self._sign_extend(self._read(op.inputs[1]), size)
        self._write(op.output, 1 if a <= b else 0)

    def _op_int_less(self, op) -> None:
        a, b = self._read(op.inputs[0]), self._read(op.inputs[1])
        self._write(op.output, 1 if a < b else 0)

    def _op_int_lessequal(self, op) -> None:
        a, b = self._read(op.inputs[0]), self._read(op.inputs[1])
        self._write(op.output, 1 if a <= b else 0)

    def _op_int_zext(self, op) -> None:
        self._write(op.output, self._read(op.inputs[0]))

    def _op_int_sext(self, op) -> None:
        val = self._sign_extend(self._read(op.inputs[0]), op.inputs[0].size)
        self._write(op.output, val)

    def _op_int_add(self, op) -> None:
        a, b = self._read(op.inputs[0]), self._read(op.inputs[1])
        self._write(op.output, a + b)

    def _op_int_sub(self, op) -> None:
        a, b = self._read(op.inputs[0]), self._read(op.inputs[1])
        self._write(op.output, a - b)

    def _op_int_carry(self, op) -> None:
        size = op.inputs[0].size
        mask = self._mask(size)
        a = self._read(op.inputs[0]) & mask
        b = self._read(op.inputs[1]) & mask
        self._write(op.output, 1 if (a + b) > mask else 0)

    def _op_int_scarry(self, op) -> None:
        size = op.inputs[0].size
        bits = size * 8
        mask = self._mask(size)
        a = self._read(op.inputs[0]) & mask
        b = self._read(op.inputs[1]) & mask
        result = (a + b) & mask
        sign_a = (a >> (bits - 1)) & 1
        sign_b = (b >> (bits - 1)) & 1
        sign_r = (result >> (bits - 1)) & 1
        # Signed overflow: both inputs same sign, result different sign
        self._write(op.output, 1 if (sign_a == sign_b) and (sign_a != sign_r) else 0)

    def _op_int_sborrow(self, op) -> None:
        size = op.inputs[0].size
        bits = size * 8
        mask = self._mask(size)
        a = self._read(op.inputs[0]) & mask
        b = self._read(op.inputs[1]) & mask
        result = (a - b) & mask
        sign_a = (a >> (bits - 1)) & 1
        sign_b = (b >> (bits - 1)) & 1
        sign_r = (result >> (bits - 1)) & 1
        # Signed borrow: inputs differ in sign and result sign != a sign
        self._write(op.output, 1 if (sign_a != sign_b) and (sign_r != sign_a) else 0)

    def _op_int_2comp(self, op) -> None:
        self._write(op.output, -self._read(op.inputs[0]))

    def _op_int_negate(self, op) -> None:
        val = self._read(op.inputs[0])
        self._write(op.output, ~val)

    def _op_int_xor(self, op) -> None:
        a, b = self._read(op.inputs[0]), self._read(op.inputs[1])
        self._write(op.output, a ^ b)

    def _op_int_and(self, op) -> None:
        a, b = self._read(op.inputs[0]), self._read(op.inputs[1])
        self._write(op.output, a & b)

    def _op_int_or(self, op) -> None:
        a, b = self._read(op.inputs[0]), self._read(op.inputs[1])
        self._write(op.output, a | b)

    def _op_int_left(self, op) -> None:
        a = self._read(op.inputs[0])
        b = self._read(op.inputs[1])
        self._write(op.output, a << b)

    def _op_int_right(self, op) -> None:
        a = self._read(op.inputs[0])
        b = self._read(op.inputs[1])
        mask = self._mask(op.inputs[0].size)
        self._write(op.output, (a & mask) >> b)

    def _op_int_sright(self, op) -> None:
        size = op.inputs[0].size
        a = self._sign_extend(self._read(op.inputs[0]), size)
        b = self._read(op.inputs[1])
        self._write(op.output, a >> b)

    def _op_int_mult(self, op) -> None:
        a, b = self._read(op.inputs[0]), self._read(op.inputs[1])
        self._write(op.output, a * b)

    def _op_int_div(self, op) -> None:
        a, b = self._read(op.inputs[0]), self._read(op.inputs[1])
        if b == 0:
            raise PcodeEmulatorError("Division by zero")
        self._write(op.output, a // b)

    def _op_int_sdiv(self, op) -> None:
        size = op.inputs[0].size
        a = self._sign_extend(self._read(op.inputs[0]), size)
        b = self._sign_extend(self._read(op.inputs[1]), size)
        if b == 0:
            raise PcodeEmulatorError("Signed division by zero")
        # Python's // truncates toward negative infinity; C truncates toward zero
        result = int(a / b)  # truncate toward zero
        self._write(op.output, result)

    def _op_int_rem(self, op) -> None:
        a, b = self._read(op.inputs[0]), self._read(op.inputs[1])
        if b == 0:
            raise PcodeEmulatorError("Remainder by zero")
        self._write(op.output, a % b)

    def _op_int_srem(self, op) -> None:
        size = op.inputs[0].size
        a = self._sign_extend(self._read(op.inputs[0]), size)
        b = self._sign_extend(self._read(op.inputs[1]), size)
        if b == 0:
            raise PcodeEmulatorError("Signed remainder by zero")
        # C-style: result has sign of dividend
        result = a - int(a / b) * b
        self._write(op.output, result)

    # -- Boolean ops --

    def _op_bool_negate(self, op) -> None:
        val = self._read(op.inputs[0])
        self._write(op.output, 1 if (val & 1) == 0 else 0)

    def _op_bool_xor(self, op) -> None:
        a = self._read(op.inputs[0]) & 1
        b = self._read(op.inputs[1]) & 1
        self._write(op.output, a ^ b)

    def _op_bool_and(self, op) -> None:
        a = self._read(op.inputs[0]) & 1
        b = self._read(op.inputs[1]) & 1
        self._write(op.output, a & b)

    def _op_bool_or(self, op) -> None:
        a = self._read(op.inputs[0]) & 1
        b = self._read(op.inputs[1]) & 1
        self._write(op.output, a | b)

    # -- Bit manipulation --

    def _op_popcount(self, op) -> None:
        val = self._read(op.inputs[0])
        mask = self._mask(op.inputs[0].size)
        self._write(op.output, bin(val & mask).count("1"))

    def _op_lzcount(self, op) -> None:
        size = op.inputs[0].size
        bits = size * 8
        mask = self._mask(size)
        val = self._read(op.inputs[0]) & mask
        if val == 0:
            self._write(op.output, bits)
        else:
            self._write(op.output, bits - val.bit_length())

    # -- Subpiece / Piece --

    def _op_subpiece(self, op) -> None:
        val = self._read(op.inputs[0])
        byte_offset = self._read(op.inputs[1])
        shifted = val >> (byte_offset * 8)
        self._write(op.output, shifted)

    def _op_piece(self, op) -> None:
        hi = self._read(op.inputs[0])
        lo = self._read(op.inputs[1])
        lo_bits = op.inputs[1].size * 8
        self._write(op.output, (hi << lo_bits) | lo)


# -- Dispatch table --
_OP_DISPATCH = {
    OpCode.IMARK: PcodeEmulator._op_imark,
    OpCode.COPY: PcodeEmulator._op_copy,
    OpCode.LOAD: PcodeEmulator._op_load,
    OpCode.STORE: PcodeEmulator._op_store_fixed,
    OpCode.BRANCH: PcodeEmulator._op_branch,
    OpCode.CBRANCH: PcodeEmulator._op_cbranch,
    OpCode.INT_EQUAL: PcodeEmulator._op_int_equal,
    OpCode.INT_NOTEQUAL: PcodeEmulator._op_int_notequal,
    OpCode.INT_SLESS: PcodeEmulator._op_int_sless,
    OpCode.INT_SLESSEQUAL: PcodeEmulator._op_int_slessequal,
    OpCode.INT_LESS: PcodeEmulator._op_int_less,
    OpCode.INT_LESSEQUAL: PcodeEmulator._op_int_lessequal,
    OpCode.INT_ZEXT: PcodeEmulator._op_int_zext,
    OpCode.INT_SEXT: PcodeEmulator._op_int_sext,
    OpCode.INT_ADD: PcodeEmulator._op_int_add,
    OpCode.INT_SUB: PcodeEmulator._op_int_sub,
    OpCode.INT_CARRY: PcodeEmulator._op_int_carry,
    OpCode.INT_SCARRY: PcodeEmulator._op_int_scarry,
    OpCode.INT_SBORROW: PcodeEmulator._op_int_sborrow,
    OpCode.INT_2COMP: PcodeEmulator._op_int_2comp,
    OpCode.INT_NEGATE: PcodeEmulator._op_int_negate,
    OpCode.INT_XOR: PcodeEmulator._op_int_xor,
    OpCode.INT_AND: PcodeEmulator._op_int_and,
    OpCode.INT_OR: PcodeEmulator._op_int_or,
    OpCode.INT_LEFT: PcodeEmulator._op_int_left,
    OpCode.INT_RIGHT: PcodeEmulator._op_int_right,
    OpCode.INT_SRIGHT: PcodeEmulator._op_int_sright,
    OpCode.INT_MULT: PcodeEmulator._op_int_mult,
    OpCode.INT_DIV: PcodeEmulator._op_int_div,
    OpCode.INT_SDIV: PcodeEmulator._op_int_sdiv,
    OpCode.INT_REM: PcodeEmulator._op_int_rem,
    OpCode.INT_SREM: PcodeEmulator._op_int_srem,
    OpCode.BOOL_NEGATE: PcodeEmulator._op_bool_negate,
    OpCode.BOOL_XOR: PcodeEmulator._op_bool_xor,
    OpCode.BOOL_AND: PcodeEmulator._op_bool_and,
    OpCode.BOOL_OR: PcodeEmulator._op_bool_or,
    OpCode.POPCOUNT: PcodeEmulator._op_popcount,
    OpCode.LZCOUNT: PcodeEmulator._op_lzcount,
    OpCode.SUBPIECE: PcodeEmulator._op_subpiece,
    OpCode.PIECE: PcodeEmulator._op_piece,
}


# ---------------------------------------------------------------------------
# Sleigh Oracle Provider
# ---------------------------------------------------------------------------

# Maps Mergen register names to pypcode register names (they happen to match
# for x86_64 GP registers).
_MERGEN_TO_SLEIGH_REG = {
    "RAX": "RAX", "RBX": "RBX", "RCX": "RCX", "RDX": "RDX",
    "RSI": "RSI", "RDI": "RDI", "RBP": "RBP", "RSP": "RSP",
    "R8": "R8", "R9": "R9", "R10": "R10", "R11": "R11",
    "R12": "R12", "R13": "R13", "R14": "R14", "R15": "R15",
    "RIP": "RIP",
}

# Maps Mergen flag names to pypcode individual flag register names.
_MERGEN_FLAG_TO_SLEIGH = {
    "FLAG_CF": "CF",
    "FLAG_PF": "PF",
    "FLAG_AF": "AF",
    "FLAG_ZF": "ZF",
    "FLAG_SF": "SF",
    "FLAG_TF": "TF",
    "FLAG_IF": "IF",
    "FLAG_DF": "DF",
    "FLAG_OF": "OF",
}


class SleighOracleProvider:
    """Oracle provider that uses Ghidra's SLEIGH P-code for x86_64 emulation."""

    name = "sleigh"

    def __init__(self) -> None:
        try:
            from pypcode import Context as _Ctx
        except ImportError as exc:
            raise RuntimeError(
                "Sleigh provider requires `pypcode`. Install with `pip install pypcode`."
            ) from exc
        self._ctx = _Ctx("x86:LE:64:default")
        self._regs = self._ctx.registers  # name -> Varnode
        self._af_offset = self._regs["AF"].offset  # 0x204 for x86_64

    @staticmethod
    def _find_af_operands(ops: list, state: 'PcodeEmulatorState'):
        """Find original operand values for AF computation.

        Scans P-code for the first INT_ADD/INT_SUB/INT_2COMP whose inputs
        come from register space (the original instruction operands).  Also
        finds the final output location of the arithmetic chain (which may be
        a register for ADD/SUB or a unique temp for CMP).

        Returns (pre_a, pre_b, dest_space, dest_offset, dest_size) or None.
        After execution: AF = ((pre_a ^ pre_b ^ post_result) >> 4) & 1.

        Limitation: this heuristic works for ADD, SUB, CMP, NEG, INC, DEC.
        For ADC/SBB, SLEIGH emits chained INT_ADDs (one for operands, one for
        carry), and this heuristic may capture operands from the wrong ADD,
        producing incorrect AF.  Acceptable for a cross-validation oracle.
        """
        pre_a = pre_b = None
        # Track the last INT_ADD/INT_SUB/INT_2COMP output that writes to a
        # GP register (preferred) or falling back to any space (for CMP).
        dest_gp = None   # (space, offset, size) — register-space output
        dest_any = None  # fallback for CMP-style ops

        for op in ops:
            if op.opcode == OpCode.INT_2COMP:
                inp = op.inputs[0]
                if inp.space.name == 'register':
                    pre_a = 0
                    pre_b = state.read('register', inp.offset, inp.size)
                    out = op.output
                    dest_gp = dest_any = (out.space.name, out.offset, out.size)
                    break
            elif op.opcode in (OpCode.INT_ADD, OpCode.INT_SUB):
                a_vn, b_vn = op.inputs[0], op.inputs[1]
                # Capture original operands from the first register-input op
                if pre_a is None:
                    a_is_reg = a_vn.space.name == 'register'
                    b_is_reg_or_const = b_vn.space.name in ('register', 'const')
                    if a_is_reg and b_is_reg_or_const:
                        pre_a = state.read('register', a_vn.offset, a_vn.size)
                        pre_b = state.read(b_vn.space.name, b_vn.offset, b_vn.size)
                if op.output:
                    loc = (op.output.space.name, op.output.offset, op.output.size)
                    dest_any = loc
                    if op.output.space.name == 'register':
                        dest_gp = loc

        dest = dest_gp or dest_any
        if pre_a is not None and dest is not None:
            return (pre_a, pre_b, *dest)
        return None

    def emulate(self, case: dict):
        """Emulate a single instruction and return an OracleResult-compatible dict."""
        instruction_bytes = bytes(case["instruction_bytes"])
        if not instruction_bytes:
            raise PcodeEmulatorError(f"Case '{case.get('name', '?')}' has no instruction bytes")

        # 1. Set up emulator state
        state = PcodeEmulatorState()
        state.map_memory(DEFAULT_CODE_ADDRESS, DEFAULT_CODE_SIZE)
        state.map_memory(DEFAULT_STACK_ADDRESS, DEFAULT_STACK_SIZE)
        state.write_mem(DEFAULT_CODE_ADDRESS, instruction_bytes)

        # 2. Set initial RSP
        rsp_vn = self._regs["RSP"]
        state.write(rsp_vn.space.name, rsp_vn.offset, rsp_vn.size,
                     DEFAULT_STACK_ADDRESS + DEFAULT_STACK_SIZE - 0x80)

        # 3. Set initial RIP
        rip_vn = self._regs["RIP"]
        state.write(rip_vn.space.name, rip_vn.offset, rip_vn.size,
                     DEFAULT_CODE_ADDRESS)

        # 4. Apply initial register values
        initial = case.get("initial", {})
        for reg_name, value in initial.get("registers", {}).items():
            sleigh_name = _MERGEN_TO_SLEIGH_REG.get(reg_name)
            if sleigh_name is None:
                raise PcodeEmulatorError(f"Unknown register '{reg_name}'")
            vn = self._regs[sleigh_name]
            int_val = int(value, 0) if isinstance(value, str) else int(value)
            state.write(vn.space.name, vn.offset, vn.size, int_val)

        # 5. Apply initial flags
        for flag_name, bit_value in initial.get("flags", {}).items():
            sleigh_flag = _MERGEN_FLAG_TO_SLEIGH.get(flag_name)
            if sleigh_flag is None:
                raise PcodeEmulatorError(f"Unknown flag '{flag_name}'")
            vn = self._regs[sleigh_flag]
            state.write(vn.space.name, vn.offset, vn.size, int(bit_value) & 1)

        # 6. Translate instruction to P-code
        translation = self._ctx.translate(
            instruction_bytes,
            base_address=DEFAULT_CODE_ADDRESS,
            max_instructions=1,
        )

        # 6b. Snapshot pre-execution register values for AF computation.
        #     Ghidra's SLEIGH spec never writes AF; we compute it from
        #     the original operands of the first register-space INT_ADD/
        #     INT_SUB/INT_2COMP and the post-execution result.
        af_pre_operands = self._find_af_operands(translation.ops, state)

        # 7. Execute P-code
        emu = PcodeEmulator(state)
        emu.execute(translation.ops)

        # 8. Read back expected registers
        expected_spec = case.get("expected", {})
        out_registers: Dict[str, int] = {}
        for reg_name in expected_spec.get("registers", {}).keys():
            sleigh_name = _MERGEN_TO_SLEIGH_REG.get(reg_name)
            if sleigh_name is None:
                raise PcodeEmulatorError(f"Unknown expected register '{reg_name}'")
            vn = self._regs[sleigh_name]
            out_registers[reg_name] = state.read(vn.space.name, vn.offset, vn.size)

        # 9. Read back expected flags
        out_flags: Dict[str, int] = {}
        for flag_name in expected_spec.get("flags", {}).keys():
            sleigh_flag = _MERGEN_FLAG_TO_SLEIGH.get(flag_name)
            if sleigh_flag is None:
                raise PcodeEmulatorError(f"Unknown expected flag '{flag_name}'")
            if flag_name == "FLAG_AF" and af_pre_operands is not None:
                # Compute AF from original operands and post-execution result
                pre_a, pre_b, dest_space, dest_off, dest_size = af_pre_operands
                post_result = state.read(dest_space, dest_off, dest_size)
                out_flags[flag_name] = ((pre_a ^ pre_b ^ post_result) >> 4) & 1
            else:
                vn = self._regs[sleigh_flag]
                out_flags[flag_name] = state.read(vn.space.name, vn.offset, vn.size) & 1

        return SleighOracleResult(registers=out_registers, flags=out_flags)
