/* PC-state VM that processes u8 bytes per iteration (8-bit stride):
 *
 *   n = (x & 7) + 1;     // 1..8 byte iters
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     uint64_t b = s & 0xFF;
 *     r = r ^ (b * b);    // u8 squared, XOR-folded
 *     s >>= 8;
 *   }
 *   return r;
 *
 * Lift target: vm_byte_xormul64_loop_target.
 *
 * Distinct from:
 *   - vm_word_xormul64_loop  (16-bit word stride)
 *   - vm_bytesq_sum64_loop   (byte squared, ADD-folded - same stride)
 *   - vm_pair_xormul_byte64_loop (2 bytes per iter)
 *
 * Tests u8 (zext-i8) self-multiply per iteration with XOR fold.
 * Byte-stride consumption with `& 0xFF` mask + lshr 8 advance.
 * All-0xFF input: each iter b=0xFF, b*b=0xFE01, eight XORs cancel.
 */
#include <stdio.h>
#include <stdint.h>

enum BxmVmPc {
    BXM_INIT_ALL = 0,
    BXM_CHECK    = 1,
    BXM_BODY     = 2,
    BXM_INC      = 3,
    BXM_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_byte_xormul64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = BXM_INIT_ALL;

    while (1) {
        if (pc == BXM_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = BXM_CHECK;
        } else if (pc == BXM_CHECK) {
            pc = (i < n) ? BXM_BODY : BXM_HALT;
        } else if (pc == BXM_BODY) {
            uint64_t b = s & 0xFFull;
            r = r ^ (b * b);
            s = s >> 8;
            pc = BXM_INC;
        } else if (pc == BXM_INC) {
            i = i + 1ull;
            pc = BXM_CHECK;
        } else if (pc == BXM_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_byte_xormul64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_byte_xormul64_loop_target(0xCAFEBABEull));
    return 0;
}
