/* PC-state VM running an i64 SIGNED-max reduction over a derived
 * sequence.
 *   n = (x & 0x1F) + 1;
 *   m = INT64_MIN;
 *   for i in 0..n: { val = (int64_t)(x ^ (i * 0x9E3779B97F4A7C15)); if (val > m) m = val; }
 *   return m;
 * Lift target: vm_smax64_loop_target.
 *
 * Distinct from vm_minarray_loop (i32 min via comparison reduction):
 * exercises i64 signed-max via icmp sgt + conditional assignment.  The
 * golden-ratio multiplier produces input-dependent values that span
 * positive and negative i64 ranges across iterations.
 */
#include <stdio.h>
#include <stdint.h>

enum SmVmPc {
    SM_LOAD       = 0,
    SM_INIT       = 1,
    SM_LOOP_CHECK = 2,
    SM_LOOP_BODY  = 3,
    SM_LOOP_INC   = 4,
    SM_HALT       = 5,
};

__declspec(noinline)
int64_t vm_smax64_loop_target(uint64_t x) {
    int     idx = 0;
    int     n   = 0;
    uint64_t xx = 0;
    int64_t m   = 0;
    int     pc  = SM_LOAD;

    while (1) {
        if (pc == SM_LOAD) {
            n  = (int)(x & 0x1Full) + 1;
            xx = x;
            m  = (int64_t)0x8000000000000000ll;  /* INT64_MIN */
            pc = SM_INIT;
        } else if (pc == SM_INIT) {
            idx = 0;
            pc = SM_LOOP_CHECK;
        } else if (pc == SM_LOOP_CHECK) {
            pc = (idx < n) ? SM_LOOP_BODY : SM_HALT;
        } else if (pc == SM_LOOP_BODY) {
            int64_t val = (int64_t)(xx ^ ((uint64_t)idx * 0x9E3779B97F4A7C15ull));
            if (val > m) {
                m = val;
            }
            pc = SM_LOOP_INC;
        } else if (pc == SM_LOOP_INC) {
            idx = idx + 1;
            pc = SM_LOOP_CHECK;
        } else if (pc == SM_HALT) {
            return m;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_smax64(0xCAFE)=%lld vm_smax64(0xCAFEBABE)=%lld\n",
           (long long)vm_smax64_loop_target(0xCAFEull),
           (long long)vm_smax64_loop_target(0xCAFEBABEull));
    return 0;
}
