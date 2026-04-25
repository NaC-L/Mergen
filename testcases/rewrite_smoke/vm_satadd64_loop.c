/* PC-state VM running an i64 saturating-add accumulator with overflow
 * detection.
 *   inc = x | 1; n = (x & 7) + 1; result = 0;
 *   for i in 0..n: { s = result + inc; if (s < result) result = MAX; else result = s; }
 *   return result;
 * Lift target: vm_satadd64_loop_target.
 *
 * Distinct from vm_saturating_loop (i32 saturating sum): exercises i64
 * unsigned-overflow detection (icmp ult i64) with branchy clamp inside
 * a variable-trip loop body on full uint64_t state.
 */
#include <stdio.h>
#include <stdint.h>

enum SaVmPc {
    SA_LOAD       = 0,
    SA_INIT       = 1,
    SA_LOOP_CHECK = 2,
    SA_LOOP_BODY  = 3,
    SA_LOOP_INC   = 4,
    SA_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_satadd64_loop_target(uint64_t x) {
    int      idx    = 0;
    int      n      = 0;
    uint64_t inc    = 0;
    uint64_t result = 0;
    int      pc     = SA_LOAD;

    while (1) {
        if (pc == SA_LOAD) {
            inc    = x | 1ull;
            n      = (int)(x & 7ull) + 1;
            result = 0ull;
            pc = SA_INIT;
        } else if (pc == SA_INIT) {
            idx = 0;
            pc = SA_LOOP_CHECK;
        } else if (pc == SA_LOOP_CHECK) {
            pc = (idx < n) ? SA_LOOP_BODY : SA_HALT;
        } else if (pc == SA_LOOP_BODY) {
            uint64_t s = result + inc;
            if (s < result) {
                result = 0xFFFFFFFFFFFFFFFFull;
            } else {
                result = s;
            }
            pc = SA_LOOP_INC;
        } else if (pc == SA_LOOP_INC) {
            idx = idx + 1;
            pc = SA_LOOP_CHECK;
        } else if (pc == SA_HALT) {
            return result;
        } else {
            return 0ull;
        }
    }
}

int main(void) {
    printf("vm_satadd64(0x8000000000000001)=%llu vm_satadd64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_satadd64_loop_target(0x8000000000000001ull),
           (unsigned long long)vm_satadd64_loop_target(0xCAFEBABEull));
    return 0;
}
