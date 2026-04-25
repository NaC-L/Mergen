/* PC-state VM running a three-op single-state chain over n iterations:
 *
 *   n = (x & 7) + 1;
 *   r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = r ^ x;
 *     r = r * 0x1000193ull;     // 24-bit FNV-32 prime
 *     r = r + x;
 *   }
 *   return r;
 *
 * Lift target: vm_xormuladd_chain64_loop_target.
 *
 * Distinct from:
 *   - vm_murmurstep64_loop  (xor-mul-lshr fold; 64-bit magic)
 *   - vm_fmix_chain64_loop  (xor-mul-xor-mul; two 64-bit magics; no add)
 *   - vm_xxhmix64_loop      (xor-byte mul; post-loop fold)
 *   - vm_horner64_loop      (poly evaluation)
 *
 * Three sequential ops on a single i64 accumulator: xor with input,
 * multiply by 24-bit prime, add input.  No lshr fold; the multiply
 * uses a small-magic constant unlike the 64-bit Murmur/xxhash magics.
 */
#include <stdio.h>
#include <stdint.h>

enum XmVmPc {
    XM_INIT_ALL = 0,
    XM_CHECK    = 1,
    XM_BODY     = 2,
    XM_INC      = 3,
    XM_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_xormuladd_chain64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = XM_INIT_ALL;

    while (1) {
        if (pc == XM_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            r = 0ull;
            i = 0ull;
            pc = XM_CHECK;
        } else if (pc == XM_CHECK) {
            pc = (i < n) ? XM_BODY : XM_HALT;
        } else if (pc == XM_BODY) {
            r = r ^ x;
            r = r * 0x1000193ull;
            r = r + x;
            pc = XM_INC;
        } else if (pc == XM_INC) {
            i = i + 1ull;
            pc = XM_CHECK;
        } else if (pc == XM_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_xormuladd_chain64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_xormuladd_chain64_loop_target(0xCAFEBABEull));
    return 0;
}
