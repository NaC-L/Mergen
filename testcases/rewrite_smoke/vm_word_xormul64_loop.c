/* PC-state VM that processes u16 words per iteration (16-bit stride):
 *
 *   n = (x & 3) + 1;     // 1..4 word iters
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     uint64_t w = s & 0xFFFF;
 *     r = r ^ (w * w);    // u16 squared, XOR-folded
 *     s >>= 16;
 *   }
 *   return r;
 *
 * Lift target: vm_word_xormul64_loop_target.
 *
 * Distinct from:
 *   - vm_bytesq_sum64_loop     (byte squared, ADD-folded - 8-bit stride)
 *   - vm_pair_xormul_byte64_loop (2 BYTES per iter - 16-bit stride but byte ops)
 *   - vm_quad_byte_xor64_loop  (4 bytes per iter, 32-bit stride)
 *
 * Tests u16 (zext-i16) self-multiply per iteration with XOR fold.
 * Word-stride consumption with `& 0xFFFF` mask + lshr 16 advance.
 * All-0xFF input: each iter w=0xFFFF, w*w=0xFFFE0001, four XORs cancel.
 */
#include <stdio.h>
#include <stdint.h>

enum WxVmPc {
    WX_INIT_ALL = 0,
    WX_CHECK    = 1,
    WX_BODY     = 2,
    WX_INC      = 3,
    WX_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_word_xormul64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = WX_INIT_ALL;

    while (1) {
        if (pc == WX_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = WX_CHECK;
        } else if (pc == WX_CHECK) {
            pc = (i < n) ? WX_BODY : WX_HALT;
        } else if (pc == WX_BODY) {
            uint64_t w = s & 0xFFFFull;
            r = r ^ (w * w);
            s = s >> 16;
            pc = WX_INC;
        } else if (pc == WX_INC) {
            i = i + 1ull;
            pc = WX_CHECK;
        } else if (pc == WX_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_word_xormul64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_word_xormul64_loop_target(0xCAFEBABEull));
    return 0;
}
