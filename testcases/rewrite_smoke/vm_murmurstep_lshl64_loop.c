/* PC-state VM that drives a Murmur-style mix-step chain with a
 * LEFT-SHIFT fold instead of the canonical right-shift fold:
 *
 *   n = (x & 7) + 1;
 *   r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = (r ^ x) * 0xC6A4A7935BD1E995ull;
 *     r = r ^ (r << 47);                       // SHL instead of LSHR
 *   }
 *   return r;
 *
 * Lift target: vm_murmurstep_lshl64_loop_target.
 *
 * Distinct from:
 *   - vm_murmurstep64_loop (sister: r ^= (r >> 47) instead of r ^= (r << 47))
 *
 * Same xor-mul fold structure as the canonical Murmur step, but the
 * second xor uses a left shift to feed the low bits up.  Tests the
 * lifter's lshr/shl swap inside an xor-mul chain across live state.
 */
#include <stdio.h>
#include <stdint.h>

enum MmlVmPc {
    MML_INIT_ALL = 0,
    MML_CHECK    = 1,
    MML_MIX_MUL  = 2,
    MML_MIX_FOLD = 3,
    MML_INC      = 4,
    MML_HALT     = 5,
};

__declspec(noinline)
uint64_t vm_murmurstep_lshl64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = MML_INIT_ALL;

    while (1) {
        if (pc == MML_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            r = 0ull;
            i = 0ull;
            pc = MML_CHECK;
        } else if (pc == MML_CHECK) {
            pc = (i < n) ? MML_MIX_MUL : MML_HALT;
        } else if (pc == MML_MIX_MUL) {
            r = (r ^ x) * 0xC6A4A7935BD1E995ull;
            pc = MML_MIX_FOLD;
        } else if (pc == MML_MIX_FOLD) {
            r = r ^ (r << 47);
            pc = MML_INC;
        } else if (pc == MML_INC) {
            i = i + 1ull;
            pc = MML_CHECK;
        } else if (pc == MML_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_murmurstep_lshl64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_murmurstep_lshl64_loop_target(0xCAFEBABEull));
    return 0;
}
