/* PC-state VM running Horner-style polynomial evaluation on full uint64_t
 * with u32 dword coefficients:
 *   n = (x & 1) + 1;
 *   p = ((x >> 32) & 0xFFFFFFFF) + 1;
 *   for i in 0..n: c = (x >> (i*32)) & 0xFFFFFFFF; s = s * p + c;
 *   return s;
 * Lift target: vm_horner_dword64_loop_target.
 *
 * Distinct from:
 *   - vm_horner_word64_loop  (16-bit coefficients)
 *   - vm_horner64_loop       (8-bit coefficients)
 *   - vm_dword_horner7_64_loop (constant multiplier 7)
 *
 * Tests u32 mul + add inside a 1..2-trip loop at u32 stride.  Multiplier
 * is parametric (input-derived high dword + 1).
 */
#include <stdio.h>
#include <stdint.h>

enum HndVmPc {
    HND_LOAD       = 0,
    HND_INIT       = 1,
    HND_LOOP_CHECK = 2,
    HND_LOOP_BODY  = 3,
    HND_LOOP_INC   = 4,
    HND_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_horner_dword64_loop_target(uint64_t x) {
    int      idx = 0;
    int      n   = 0;
    uint64_t p   = 0;
    uint64_t s   = 0;
    uint64_t xx  = 0;
    int      pc  = HND_LOAD;

    while (1) {
        if (pc == HND_LOAD) {
            n  = (int)(x & 1ull) + 1;
            p  = ((x >> 32) & 0xFFFFFFFFull) + 1ull;
            xx = x;
            s  = 0ull;
            pc = HND_INIT;
        } else if (pc == HND_INIT) {
            idx = 0;
            pc = HND_LOOP_CHECK;
        } else if (pc == HND_LOOP_CHECK) {
            pc = (idx < n) ? HND_LOOP_BODY : HND_HALT;
        } else if (pc == HND_LOOP_BODY) {
            uint64_t c = (xx >> (idx * 32)) & 0xFFFFFFFFull;
            s = s * p + c;
            pc = HND_LOOP_INC;
        } else if (pc == HND_LOOP_INC) {
            idx = idx + 1;
            pc = HND_LOOP_CHECK;
        } else if (pc == HND_HALT) {
            return s;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_horner_dword64(0xCAFEBABEDEADBEEF)=%llu\n",
           (unsigned long long)vm_horner_dword64_loop_target(0xCAFEBABEDEADBEEFull));
    return 0;
}
