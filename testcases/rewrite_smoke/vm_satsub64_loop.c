/* PC-state VM running an i64 saturating-sub accumulator with underflow
 * detection.
 *   dec = x | 1; n = (x & 7) + 1; result = ~0;
 *   for i in 0..n: { s = result - dec; if (s > result) result = 0; else result = s; }
 *   return result;
 * Lift target: vm_satsub64_loop_target.
 *
 * Distinct from vm_satadd64_loop (saturating add to MAX): mirrors the
 * underflow path and clamps to 0 instead of MAX.  Exercises i64
 * unsigned-underflow detection (icmp ugt i64) with branchy clamp inside
 * a variable-trip loop body on full uint64_t state.
 */
#include <stdio.h>
#include <stdint.h>

enum SsVmPc {
    SS_LOAD       = 0,
    SS_INIT       = 1,
    SS_LOOP_CHECK = 2,
    SS_LOOP_BODY  = 3,
    SS_LOOP_INC   = 4,
    SS_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_satsub64_loop_target(uint64_t x) {
    int      idx    = 0;
    int      n      = 0;
    uint64_t dec    = 0;
    uint64_t result = 0;
    int      pc     = SS_LOAD;

    while (1) {
        if (pc == SS_LOAD) {
            dec    = x | 1ull;
            n      = (int)(x & 7ull) + 1;
            result = 0xFFFFFFFFFFFFFFFFull;
            pc = SS_INIT;
        } else if (pc == SS_INIT) {
            idx = 0;
            pc = SS_LOOP_CHECK;
        } else if (pc == SS_LOOP_CHECK) {
            pc = (idx < n) ? SS_LOOP_BODY : SS_HALT;
        } else if (pc == SS_LOOP_BODY) {
            uint64_t s = result - dec;
            if (s > result) {
                result = 0ull;
            } else {
                result = s;
            }
            pc = SS_LOOP_INC;
        } else if (pc == SS_LOOP_INC) {
            idx = idx + 1;
            pc = SS_LOOP_CHECK;
        } else if (pc == SS_HALT) {
            return result;
        } else {
            return 0ull;
        }
    }
}

int main(void) {
    printf("vm_satsub64(0x8000000000000001)=%llu vm_satsub64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_satsub64_loop_target(0x8000000000000001ull),
           (unsigned long long)vm_satsub64_loop_target(0xCAFEBABEull));
    return 0;
}
