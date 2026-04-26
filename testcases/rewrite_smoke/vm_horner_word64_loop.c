/* PC-state VM running Horner-style polynomial evaluation on full uint64_t
 * with u16 word coefficients:
 *   n = (x & 3) + 1;
 *   p = ((x >> 16) & 0xFFFF) + 1;
 *   for i in 0..n: c = (x >> (i*16)) & 0xFFFF; s = s * p + c;
 *   return s;
 * Lift target: vm_horner_word64_loop_target.
 *
 * Distinct from:
 *   - vm_horner64_loop (8-bit coefficients, parametric multiplier from
 *     byte 1)
 *   - vm_var_horner_word64_loop (multiplier comes from loop counter)
 *   - vm_word_horner13_64_loop (constant multiplier 13)
 *
 * Tests u16 mul + add inside a variable-trip loop with word-walking
 * shift (loop-counter-derived shift amount) at u16 stride.  Multiplier
 * is parametric (input-derived).
 */
#include <stdio.h>
#include <stdint.h>

enum HnwVmPc {
    HNW_LOAD       = 0,
    HNW_INIT       = 1,
    HNW_LOOP_CHECK = 2,
    HNW_LOOP_BODY  = 3,
    HNW_LOOP_INC   = 4,
    HNW_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_horner_word64_loop_target(uint64_t x) {
    int      idx = 0;
    int      n   = 0;
    uint64_t p   = 0;
    uint64_t s   = 0;
    uint64_t xx  = 0;
    int      pc  = HNW_LOAD;

    while (1) {
        if (pc == HNW_LOAD) {
            n  = (int)(x & 3ull) + 1;
            p  = ((x >> 16) & 0xFFFFull) + 1ull;
            xx = x;
            s  = 0ull;
            pc = HNW_INIT;
        } else if (pc == HNW_INIT) {
            idx = 0;
            pc = HNW_LOOP_CHECK;
        } else if (pc == HNW_LOOP_CHECK) {
            pc = (idx < n) ? HNW_LOOP_BODY : HNW_HALT;
        } else if (pc == HNW_LOOP_BODY) {
            uint64_t c = (xx >> (idx * 16)) & 0xFFFFull;
            s = s * p + c;
            pc = HNW_LOOP_INC;
        } else if (pc == HNW_LOOP_INC) {
            idx = idx + 1;
            pc = HNW_LOOP_CHECK;
        } else if (pc == HNW_HALT) {
            return s;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_horner_word64(0xCAFE)=%llu\n",
           (unsigned long long)vm_horner_word64_loop_target(0xCAFEull));
    return 0;
}
