use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, MemorySize, Mnemonic, NasmFormatter, OpKind, Register, SpecializedFormatter, SpecializedFormatterTraitOptions};
use std::slice;
use std::ffi::CString;
use std::os::raw::c_char;
use memoffset::offset_of;

/// A C-compatible version of your disassembled instruction structure.

pub const PREFIX_NONE: u8 = 0;
pub const PREFIX_REP: u8 = 1;
pub const PREFIX_REPE: u8 = 1;
pub const PREFIX_REPNE: u8 = 2;
pub const PREFIX_LOCK: u8 = 3;
pub const PREFIX_END: u8 = 3;



#[derive(Debug, Clone, Copy)]
enum OperandType {
  Invalid,
  Register8,
  Register16,
  Register32,
  Register64,
  Memory8,
  Memory16,
  Memory32,
  Memory64,
  Immediate8,
  Immediate8_2nd, // enter/exit
  Immediate16,
  Immediate32,
  Immediate64
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct MergenDisassembledInstructionBase {
    pub mnemonic: u16,

    pub mem_base: u8,
    pub mem_index: u8,
    pub mem_scale: u8,


    pub stack_growth: u8,

    

    pub regs: [u8; 4],
    pub types: [u8; 4],

    pub attributes: u8,

    pub length: u8,

    pub operand_count_visible: u8,

    pub immediate: u64,

    pub mem_disp: u64, // aka imm2

    pub text: *mut i8,
}

// make sure its same as our c structure

const _: () = assert!(offset_of!(MergenDisassembledInstructionBase, mnemonic) ==  0,  "invalid offset");
const _: () = assert!(offset_of!(MergenDisassembledInstructionBase, mem_base) ==  2,  "invalid offset");
const _: () = assert!(offset_of!(MergenDisassembledInstructionBase, mem_index) ==  3,  "invalid offset");
const _: () = assert!(offset_of!(MergenDisassembledInstructionBase, mem_scale) ==  4,  "invalid offset");
const _: () = assert!(offset_of!(MergenDisassembledInstructionBase, stack_growth) ==  5,  "invalid offset");
const _: () = assert!(offset_of!(MergenDisassembledInstructionBase, regs) ==  6,  "invalid offset");
const _: () = assert!(offset_of!(MergenDisassembledInstructionBase, types) ==  10,  "invalid offset");
const _: () = assert!(offset_of!(MergenDisassembledInstructionBase, attributes) ==  14,  "invalid offset");
const _: () = assert!(offset_of!(MergenDisassembledInstructionBase, length) ==  15,  "invalid offset");
const _: () = assert!(offset_of!(MergenDisassembledInstructionBase, operand_count_visible) ==  16,  "invalid offset");
const _: () = assert!(offset_of!(MergenDisassembledInstructionBase, immediate) ==  24,  "invalid offset");
const _: () = assert!(offset_of!(MergenDisassembledInstructionBase, mem_disp) ==  32,  "invalid offset");
const _: () = assert!(offset_of!(MergenDisassembledInstructionBase, text) ==  40,  "invalid offset");

fn has_64bit_immediate(instr: &Instruction) -> bool {
    for i in 0..instr.op_count() {
        match instr.op_kind(i) {
            OpKind::Immediate64 => return true,
            _ => continue,
        }
    }
    false
}

fn is_relative_jump(instr: &Instruction) -> bool {
    if instr.memory_base() == Register::RIP {
        return true;
    }
    // at max, its 5, use constants to unroll & less lookup
    for i in 0..5{
        match instr.op_kind(i) {
            // if nearbranch, base isnt rip, kinda annoyin
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => return true,
            _ => {}
        }
    }
    false
}

fn convert_type_to_mergen(inst : &Instruction,  index : u32) -> OperandType {
    
    match inst.op_kind(index) {
        OpKind::Register => {
            match inst.op_register(index).size() {
                1 => { return OperandType::Register8; },
                2 => {return OperandType::Register16},
                4 => {return OperandType::Register32},
                8 => {return OperandType::Register64},
                // 16 => OperandType::Register128,
                0 => {return OperandType::Invalid},
                _ => {panic!("Unhandled register size: {}", inst.op_register(index).size());},
            }
        },
        OpKind::Immediate8 => { return OperandType::Immediate8 },
        OpKind::Immediate8_2nd => { return OperandType::Immediate8_2nd },
        OpKind::Immediate16 => {return OperandType::Immediate16},
        OpKind::Immediate32 => return OperandType::Immediate32,
        OpKind::Immediate64 => return OperandType::Immediate64,
        
        // these get Sign Extended, but we smart, we know what to sign extend XD
        // todo: add these types to enum
        OpKind::Immediate8to16 => return OperandType::Immediate8,
        OpKind::Immediate8to32 => return OperandType::Immediate8,
        OpKind::Immediate8to64 => return OperandType::Immediate8,
        OpKind::Immediate32to64 => return OperandType::Immediate32,

        OpKind::NearBranch16 => return OperandType::Immediate16,
        OpKind::NearBranch32 => return OperandType::Immediate32,
        OpKind::NearBranch64 => return OperandType::Immediate64,

        OpKind::FarBranch16 => return OperandType::Immediate16,
        OpKind::FarBranch32 => return OperandType::Immediate32,
        // OpKind::FarBranch64 => return OperandType::Immediate64,
        
        // OpKind::NearBranch16 => return OperandType::Immediate16,

        OpKind::Memory => {
            match inst.memory_size().size() {
                0 => {
                    /*                    
                    if inst.mnemonic() == Mnemonic::Lea {
                        return convert_type_to_mergen(&inst, 0);
                    } 
                    */
                    return OperandType::Invalid;
                },
                1 => {return OperandType::Memory8},
                2 => {return OperandType::Memory16},
                4 => {return OperandType::Memory32},
                8 => {return OperandType::Memory64},
                // 16 => OperandType::Memory128
                _ => {println!("{:?}", inst.memory_size());panic!("Unhandled memory size: {}", inst.memory_size().size())},
            }
        },

        _ => return OperandType::Invalid,
    }
}


/// Decodes a machine-code buffer and translates the first instruction into a
/// C‑compatible MergenDisassembledInstructionBase structure.
///
/// # Parameters
///
/// - `code_ptr`: Pointer to the machine code bytes.
/// - `len`: Length of the code in bytes.
/// - `out`: Pointer to a MergenDisassembledInstructionBase structure that will be filled.
///
/// # Returns
///
/// Returns 0 on success, or -1 if the input pointers are null or length is 0.
#[no_mangle]
pub extern "C" fn disas(
    out: *mut MergenDisassembledInstructionBase,
    code_ptr: *const u8,
    len: usize
) -> i32 {
    // Fast null/length check
    if out.is_null() || code_ptr.is_null() || len == 0 {
        return -1;
    }

    // SAFETY: we've checked that pointers are non-null and len > 0
    let code = unsafe { std::slice::from_raw_parts(code_ptr, len) };
    let mut decoder = Decoder::new(64, code, DecoderOptions::NONE);
    let instr = decoder.decode();


    // Precompute commonly used values
    let disp64 = instr.memory_displacement64();
    let instr_len = instr.len() as u64;
    let is_rel = is_relative_jump(&instr);
    let has_imm64 = has_64bit_immediate(&instr);

    // Compute immediate in one branch sequence
    let immediate = if is_rel {
        // relative jump: displacement minus instruction length
        disp64.wrapping_sub(instr_len)
    } else if has_imm64 {
        instr.immediate64() as u64
    } else {
        instr.immediate32() as u64
    };

    // Compute prefix attributes via bitflags
    let mut attrs = 0u8;
    if instr.has_rep_prefix()   { attrs = PREFIX_REP as u8; }
    if instr.has_repne_prefix() { attrs = PREFIX_REPNE as u8; }
    if instr.has_lock_prefix()  { attrs = PREFIX_LOCK as u8; }

    // Build output struct in one go
    let out_value = MergenDisassembledInstructionBase {
        mnemonic: instr.mnemonic() as u16,
        mem_base:   instr.memory_base() as u8,
        mem_index:  instr.memory_index() as u8,
        mem_scale:  instr.memory_index_scale() as u8,
        mem_disp:   if is_rel { disp64.wrapping_sub(instr_len) } else { disp64 },
        stack_growth: instr.stack_pointer_increment().unsigned_abs() as u8,
        immediate,
        regs: [
            instr.op0_register() as u8,
            instr.op1_register() as u8,
            instr.op2_register() as u8,
            instr.op3_register() as u8,
        ],
        types: [
            convert_type_to_mergen(&instr, 0) as u8,
            convert_type_to_mergen(&instr, 1) as u8,
            convert_type_to_mergen(&instr, 2) as u8,
            convert_type_to_mergen(&instr, 3) as u8,
        ],
        operand_count_visible: instr.op_count() as u8,
        attributes: attrs,
        length: instr.len() as u8,
        text: std::ptr::null_mut()
    };

    // SAFETY: out is non-null and points to valid memory
    unsafe { std::ptr::write(out, out_value) };

    0
}

#[no_mangle]
pub extern "C" fn disas2(
    out: *mut MergenDisassembledInstructionBase,
    code_ptr: *const u8,
    len: usize,
) -> i32 {
    if out.is_null() || code_ptr.is_null() || len == 0 {
        return -1;
    }
    let code = unsafe { std::slice::from_raw_parts(code_ptr, len) };
    let mut decoder = Decoder::new(64, code, DecoderOptions::NONE);
    let instr = decoder.decode();
    struct MyTraitOptions;
    impl SpecializedFormatterTraitOptions for MyTraitOptions {
        // If you never create a db/dw/dd/dq 'instruction', we don't need this feature.
        const ENABLE_DB_DW_DD_DQ: bool = false;
        // For a few percent faster code, you can also override `verify_output_has_enough_bytes_left()` and return `false`
        unsafe fn verify_output_has_enough_bytes_left() -> bool {
             false
        }
    }
    type MyFormatter = SpecializedFormatter<MyTraitOptions>;
    // Format instruction text
    let mut formatter = MyFormatter::new();
    let mut formatted = String::new();
    formatter.format(&instr, &mut formatted);
    let c_text = match CString::new(formatted) {
        Ok(cstr) => cstr.into_raw(),
        Err(_) => return -1,
    };

    let disp64 = instr.memory_displacement64();
    let instr_len = instr.len() as u64;
    let is_rel = is_relative_jump(&instr);
    let has_imm64 = has_64bit_immediate(&instr);

    let immediate = if is_rel {
        disp64.wrapping_sub(instr_len)
    } else if has_imm64 {
        instr.immediate64() as u64
    } else {
        instr.immediate32() as u64
    };

    let mut attrs = 0u8;
    if instr.has_rep_prefix()   { attrs |= 0b001; }
    if instr.has_repne_prefix() { attrs |= 0b010; }
    if instr.has_lock_prefix()  { attrs |= 0b100; }

    let out_value = MergenDisassembledInstructionBase {
        mnemonic: instr.mnemonic() as u16,
        mem_base: instr.memory_base() as u8,
        mem_index: instr.memory_index() as u8,
        mem_scale: instr.memory_index_scale() as u8,
        mem_disp: if is_rel { disp64.wrapping_sub(instr_len) } else { disp64 },
        stack_growth: instr.stack_pointer_increment().unsigned_abs() as u8,
        immediate,
        regs: [
            instr.op0_register() as u8,
            instr.op1_register() as u8,
            instr.op2_register() as u8,
            instr.op3_register() as u8,
        ],
        types: [
            convert_type_to_mergen(&instr, 0) as u8,
            convert_type_to_mergen(&instr, 1) as u8,
            convert_type_to_mergen(&instr, 2) as u8,
            convert_type_to_mergen(&instr, 3) as u8,
        ],
        operand_count_visible: instr.op_count() as u8,
        attributes: attrs,
        length: instr.len() as u8,
        text: c_text,
    };
    unsafe { std::ptr::write(out, out_value) };
    0
}

/// Frees a string allocated by Rust (using CString::into_raw).
///
/// # Parameters
///
/// - `s`: Pointer to the C string allocated in Rust.
#[no_mangle]
pub extern "C" fn free_rust_string(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    // Safety: reconstruct the CString so that it gets dropped.
    unsafe { let _ = CString::from_raw(s); };
}
