/* PC-state VM running an i64 abs-then-affine recurrence.
 *   val = (int64_t)x;
 *   for i in 0..n: { if (val < 0) val = -val; val = val * 3 - i; }
 *   return val;
 * Variable trip n = (x & 7) + 1.  Returns full uint64_t bit pattern.
 * Lift target: vm_abs64_loop_target.
 *
 * Distinct from vm_imported_abs_loop (i32 _abs_l intrinsic): exercises
 * i64 conditional-negate (likely lowered to llvm.abs.i64 by the
 * optimizer) followed by mul-by-3 and subtraction in a variable-trip
 * loop.  INT64_MIN excluded from inputs because -INT64_MIN is C UB.
 */
#include <stdio.h>
#include <stdint.h>

enum AbVmPc {
    AB_LOAD       = 0,
    AB_INIT       = 1,
    AB_LOOP_CHECK = 2,
    AB_LOOP_BODY  = 3,
    AB_LOOP_INC   = 4,
    AB_HALT       = 5,
};

__declspec(noinline)
int64_t vm_abs64_loop_target(int64_t x) {
    int     idx = 0;
    int     n   = 0;
    int64_t val = 0;
    int     pc  = AB_LOAD;

    while (1) {
        if (pc == AB_LOAD) {
            n   = (int)((uint64_t)x & 7ull) + 1;
            val = x;
            pc = AB_INIT;
        } else if (pc == AB_INIT) {
            idx = 0;
            pc = AB_LOOP_CHECK;
        } else if (pc == AB_LOOP_CHECK) {
            pc = (idx < n) ? AB_LOOP_BODY : AB_HALT;
        } else if (pc == AB_LOOP_BODY) {
            if (val < 0) {
                val = -val;
            }
            val = val * 3 - idx;
            pc = AB_LOOP_INC;
        } else if (pc == AB_LOOP_INC) {
            idx = idx + 1;
            pc = AB_LOOP_CHECK;
        } else if (pc == AB_HALT) {
            return val;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_abs64(-1)=%lld vm_abs64(0xCAFEBABE)=%lld\n",
           (long long)vm_abs64_loop_target((int64_t)-1),
           (long long)vm_abs64_loop_target((int64_t)0xCAFEBABEll));
    return 0;
}
