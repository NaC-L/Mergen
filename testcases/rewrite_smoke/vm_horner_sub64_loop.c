/* PC-state VM running Horner-style polynomial evaluation on full
 * uint64_t with SUBTRACTIVE coefficient combine:
 *
 *   p = ((x >> 8) & 0xFF) + 1;
 *   n = (x & 7) + 1;
 *   s = 0;
 *   for i in 0..n: { c = (x >> (i*8)) & 0xFF; s = s * p - c; }
 *   return s;
 *
 * Lift target: vm_horner_sub64_loop_target.
 *
 * Distinct from:
 *   - vm_horner64_loop (sister: s = s*p + c instead of s*p - c)
 *
 * Same Horner mul-by-base byte-walking shape but combines with SUB
 * instead of ADD on each coefficient.  Tests u64 underflow inside the
 * polynomial recurrence over a symbolic shift-by-loop-counter byte
 * extraction.
 */
#include <stdio.h>
#include <stdint.h>

enum HnsVmPc {
    HNS_LOAD       = 0,
    HNS_INIT       = 1,
    HNS_LOOP_CHECK = 2,
    HNS_LOOP_BODY  = 3,
    HNS_LOOP_INC   = 4,
    HNS_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_horner_sub64_loop_target(uint64_t x) {
    int      idx = 0;
    int      n   = 0;
    uint64_t p   = 0;
    uint64_t s   = 0;
    uint64_t xx  = 0;
    int      pc  = HNS_LOAD;

    while (1) {
        if (pc == HNS_LOAD) {
            n  = (int)(x & 7ull) + 1;
            p  = ((x >> 8) & 0xFFull) + 1ull;
            xx = x;
            s  = 0ull;
            pc = HNS_INIT;
        } else if (pc == HNS_INIT) {
            idx = 0;
            pc = HNS_LOOP_CHECK;
        } else if (pc == HNS_LOOP_CHECK) {
            pc = (idx < n) ? HNS_LOOP_BODY : HNS_HALT;
        } else if (pc == HNS_LOOP_BODY) {
            uint64_t c = (xx >> (idx * 8)) & 0xFFull;
            s = s * p - c;
            pc = HNS_LOOP_INC;
        } else if (pc == HNS_LOOP_INC) {
            idx = idx + 1;
            pc = HNS_LOOP_CHECK;
        } else if (pc == HNS_HALT) {
            return s;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_horner_sub64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_horner_sub64_loop_target(0xCAFEBABEull));
    return 0;
}
