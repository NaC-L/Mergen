/* PC-state VM that processes u32 dwords per iteration:
 *
 *   n = (x & 1) + 1;     // 1..2 dword iters
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     uint64_t d = s & 0xFFFFFFFF;
 *     r = r ^ (d * 0x9E3779B9);   // golden-ratio prime mul
 *     s >>= 32;
 *   }
 *   return r;
 *
 * Lift target: vm_dword_xormul64_loop_target.
 *
 * Distinct from:
 *   - vm_word_xormul64_loop  (u16 word stride)
 *   - vm_quad_byte_xor64_loop (4 BYTES per iter)
 *   - vm_xormuladd_chain64_loop (xor + mul + add, no stride)
 *
 * Tests u32 zext-i32 reads (mask 0xFFFFFFFF) multiplied by the
 * 32-bit golden-ratio prime 0x9E3779B9 and XOR-folded into the
 * accumulator.  Stride is 32 bits per iter; loop runs 1..2 times.
 */
#include <stdio.h>
#include <stdint.h>

enum DwVmPc {
    DW_INIT_ALL = 0,
    DW_CHECK    = 1,
    DW_BODY     = 2,
    DW_INC      = 3,
    DW_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_dword_xormul64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = DW_INIT_ALL;

    while (1) {
        if (pc == DW_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = DW_CHECK;
        } else if (pc == DW_CHECK) {
            pc = (i < n) ? DW_BODY : DW_HALT;
        } else if (pc == DW_BODY) {
            uint64_t d = s & 0xFFFFFFFFull;
            r = r ^ (d * 0x9E3779B9ull);
            s = s >> 32;
            pc = DW_INC;
        } else if (pc == DW_INC) {
            i = i + 1ull;
            pc = DW_CHECK;
        } else if (pc == DW_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dword_xormul64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_dword_xormul64_loop_target(0xCAFEBABEull));
    return 0;
}
