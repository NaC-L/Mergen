/* PC-state VM finding the longest run of consecutive 1-bits anywhere in
 * a uint64_t.
 *   max_run = 0; cur = 0;
 *   for i in 0..64:
 *     if ((x >> i) & 1):
 *       cur++;
 *       if (cur > max_run) max_run = cur;
 *     else:
 *       cur = 0;
 *   return max_run;
 * 64-trip fixed loop with TWO counters (max_run, cur) where ONE branch
 * conditionally updates max_run AFTER incrementing cur, and the OTHER
 * branch resets cur.  This is the documented "single-slot dual-update"
 * shape (max_run on one branch, cur reset on the other).
 *
 * Lift target: vm_maxrun64_loop_target.
 *
 * Distinct from vm_trailingones64_loop (only trailing run): scans whole
 * input and keeps a running max-of-runs.  Two i64 counter slots updated
 * in MUTUALLY-EXCLUSIVE branches but ONE slot is conditional max-update
 * (single-slot vs dual-slot mutex).
 */
#include <stdio.h>
#include <stdint.h>

enum MrVmPc {
    MR_LOAD       = 0,
    MR_INIT       = 1,
    MR_LOOP_CHECK = 2,
    MR_LOOP_BODY  = 3,
    MR_LOOP_INC   = 4,
    MR_HALT       = 5,
};

__declspec(noinline)
int vm_maxrun64_loop_target(uint64_t x) {
    int      idx     = 0;
    int      cur     = 0;
    int      max_run = 0;
    uint64_t xx      = 0;
    int      pc      = MR_LOAD;

    while (1) {
        if (pc == MR_LOAD) {
            xx      = x;
            cur     = 0;
            max_run = 0;
            pc = MR_INIT;
        } else if (pc == MR_INIT) {
            idx = 0;
            pc = MR_LOOP_CHECK;
        } else if (pc == MR_LOOP_CHECK) {
            pc = (idx < 64) ? MR_LOOP_BODY : MR_HALT;
        } else if (pc == MR_LOOP_BODY) {
            if (((xx >> idx) & 1ull) != 0ull) {
                cur = cur + 1;
                if (cur > max_run) {
                    max_run = cur;
                }
            } else {
                cur = 0;
            }
            pc = MR_LOOP_INC;
        } else if (pc == MR_LOOP_INC) {
            idx = idx + 1;
            pc = MR_LOOP_CHECK;
        } else if (pc == MR_HALT) {
            return max_run;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_maxrun64(0xCAFE)=%d vm_maxrun64(max)=%d\n",
           vm_maxrun64_loop_target(0xCAFEull),
           vm_maxrun64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
