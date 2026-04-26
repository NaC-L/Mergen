/* PC-state VM that XOR-folds u8 bytes over n = (x & 7) + 1 iterations:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   while (n) {
 *     r = r ^ (s & 0xFF);
 *     s >>= 8;
 *     n--;
 *   }
 *   return r;
 *
 * Lift target: vm_byte_xorfold64_loop_target.
 *
 * Distinct from:
 *   - vm_byte_andfold64_loop (AND fold)
 *   - vm_byte_orfold64_loop  (OR fold)
 *   - vm_word_xorfold64_loop (XOR fold at 16-bit stride)
 *   - vm_xorbytes64_loop     (alternates xor with separate accumulator)
 *
 * Tests `xor i64` chain at byte stride.  Unlike AND/OR, XOR is not
 * monotone in either direction; identical bytes cancel.  All-FF input
 * with even n yields 0; with odd n yields 0xFF.
 */
#include <stdio.h>
#include <stdint.h>

enum BxVmPc {
    BX_INIT_ALL = 0,
    BX_CHECK    = 1,
    BX_BODY     = 2,
    BX_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_byte_xorfold64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    int      pc = BX_INIT_ALL;

    while (1) {
        if (pc == BX_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0ull;
            pc = BX_CHECK;
        } else if (pc == BX_CHECK) {
            pc = (n > 0ull) ? BX_BODY : BX_HALT;
        } else if (pc == BX_BODY) {
            r = r ^ (s & 0xFFull);
            s = s >> 8;
            n = n - 1ull;
            pc = BX_CHECK;
        } else if (pc == BX_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_byte_xorfold64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_byte_xorfold64_loop_target(0xCAFEBABEull));
    return 0;
}
