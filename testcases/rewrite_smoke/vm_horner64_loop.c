/* PC-state VM running Horner-style polynomial evaluation on full uint64_t.
 *   p = ((x >> 8) & 0xFF) + 1;
 *   n = (x & 7) + 2;
 *   for i in 0..n: { c = (x >> (i*8)) & 0xFF; s = s * p + c; }
 *   return s;
 * Returns full uint64_t.  Lift target: vm_horner64_loop_target.
 *
 * Distinct from vm_horner_signed_loop (i32 signed Horner).  Exercises
 * i64 mul + add inside a variable-trip loop with byte-walking shift
 * (loop-counter-derived shift amount).
 */
#include <stdio.h>
#include <stdint.h>

enum HnVmPc {
    HN_LOAD       = 0,
    HN_INIT       = 1,
    HN_LOOP_CHECK = 2,
    HN_LOOP_BODY  = 3,
    HN_LOOP_INC   = 4,
    HN_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_horner64_loop_target(uint64_t x) {
    int      idx = 0;
    int      n   = 0;
    uint64_t p   = 0;
    uint64_t s   = 0;
    uint64_t xx  = 0;
    int      pc  = HN_LOAD;

    while (1) {
        if (pc == HN_LOAD) {
            n  = (int)(x & 7ull) + 1;
            p  = ((x >> 8) & 0xFFull) + 1ull;
            xx = x;
            s  = 0ull;
            pc = HN_INIT;
        } else if (pc == HN_INIT) {
            idx = 0;
            pc = HN_LOOP_CHECK;
        } else if (pc == HN_LOOP_CHECK) {
            pc = (idx < n) ? HN_LOOP_BODY : HN_HALT;
        } else if (pc == HN_LOOP_BODY) {
            uint64_t c = (xx >> (idx * 8)) & 0xFFull;
            s = s * p + c;
            pc = HN_LOOP_INC;
        } else if (pc == HN_LOOP_INC) {
            idx = idx + 1;
            pc = HN_LOOP_CHECK;
        } else if (pc == HN_HALT) {
            return s;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_horner64(0xCAFE)=%llu vm_horner64(0x1FF)=%llu\n",
           (unsigned long long)vm_horner64_loop_target(0xCAFEull),
           (unsigned long long)vm_horner64_loop_target(0x1FFull));
    return 0;
}
