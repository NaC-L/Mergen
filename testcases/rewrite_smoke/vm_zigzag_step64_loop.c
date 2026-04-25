/* PC-state VM running ZigZag encoding chained over a stepped state:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     // ZigZag: (s << 1) ^ (s as i64 >> 63)
 *     enc = (s << 1) ^ (uint64_t)((int64_t)s >> 63);
 *     r = r + enc;
 *     s = s + 0x9E3779B97F4A7C15;     // golden-ratio additive step
 *   }
 *   return r;
 *
 * Lift target: vm_zigzag_step64_loop_target.
 *
 * Distinct from:
 *   - vm_splitmix64_loop (xor-mul-xor-mul-xor finalizer)
 *   - vm_xorrot64_loop   (xor + LCG mul step)
 *   - vm_signedbytesum64_loop (per-byte sext-i8)
 *
 * Tests ashr i64 ... 63 (arithmetic right shift to broadcast the sign
 * bit) inside a counter-bound loop body.  The sign-broadcast XOR with
 * shifted s implements ZigZag encoding of a signed i64; the result is
 * accumulated and the state advances by the golden-ratio additive
 * constant each iteration.
 */
#include <stdio.h>
#include <stdint.h>

enum ZzVmPc {
    ZZ_INIT_ALL = 0,
    ZZ_CHECK    = 1,
    ZZ_BODY     = 2,
    ZZ_INC      = 3,
    ZZ_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_zigzag_step64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = ZZ_INIT_ALL;

    while (1) {
        if (pc == ZZ_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = ZZ_CHECK;
        } else if (pc == ZZ_CHECK) {
            pc = (i < n) ? ZZ_BODY : ZZ_HALT;
        } else if (pc == ZZ_BODY) {
            uint64_t enc = (s << 1) ^ (uint64_t)((int64_t)s >> 63);
            r = r + enc;
            s = s + 0x9E3779B97F4A7C15ull;
            pc = ZZ_INC;
        } else if (pc == ZZ_INC) {
            i = i + 1ull;
            pc = ZZ_CHECK;
        } else if (pc == ZZ_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_zigzag_step64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_zigzag_step64_loop_target(0xCAFEBABEull));
    return 0;
}
