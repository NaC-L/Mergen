/* PC-state VM that drives a Murmur-style mix-step chain over n iterations:
 *
 *   n = (x & 7) + 1;
 *   r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = (r ^ x) * 0xC6A4A7935BD1E995ull;
 *     r = r ^ (r >> 47);
 *   }
 *   return r;
 *
 * Lift target: vm_murmurstep64_loop_target.
 *
 * Distinct from:
 *   - vm_xorrot64_loop  (xor + LCG mul/add step)
 *   - vm_djb264_loop    (additive multiplier *33 hash)
 *   - vm_fmix64_loop    (single Murmur finalizer, no loop)
 *   - vm_horner64_loop  (polynomial evaluation)
 *
 * Single i64 accumulator threaded through xor with the input then
 * multiplied by the Murmur magic and XOR-folded with its own high
 * 17 bits.  Tests xor-mul-lshr chain on a live state across loop
 * iterations.
 */
#include <stdio.h>
#include <stdint.h>

enum MmVmPc {
    MM_INIT_ALL = 0,
    MM_CHECK    = 1,
    MM_MIX_MUL  = 2,
    MM_MIX_FOLD = 3,
    MM_INC      = 4,
    MM_HALT     = 5,
};

__declspec(noinline)
uint64_t vm_murmurstep64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = MM_INIT_ALL;

    while (1) {
        if (pc == MM_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            r = 0ull;
            i = 0ull;
            pc = MM_CHECK;
        } else if (pc == MM_CHECK) {
            pc = (i < n) ? MM_MIX_MUL : MM_HALT;
        } else if (pc == MM_MIX_MUL) {
            r = (r ^ x) * 0xC6A4A7935BD1E995ull;
            pc = MM_MIX_FOLD;
        } else if (pc == MM_MIX_FOLD) {
            r = r ^ (r >> 47);
            pc = MM_INC;
        } else if (pc == MM_INC) {
            i = i + 1ull;
            pc = MM_CHECK;
        } else if (pc == MM_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_murmurstep64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_murmurstep64_loop_target(0xCAFEBABEull));
    return 0;
}
