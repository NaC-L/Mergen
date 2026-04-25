/* PC-state VM that walks a binary-tree-shaped state recurrence driven
 * by the bits of x at each iteration index.
 *   s = 0; n = (x & 0x3F) + 1;
 *   for i in 0..n:
 *     bit = (x >> i) & 1
 *     if bit: s = s * 3 + 1
 *     else:   s = s * 2
 *   return s;
 * Returns full uint64_t.  Lift target: vm_treepath64_loop_target.
 *
 * Distinct from existing samples: the per-iteration BRANCH direction is
 * determined by reading a different bit of the input each time
 * (variable shift amount = loop counter).  Exercises i64 mul-by-2 vs
 * mul-by-3+1 conditional-update inside a variable-trip loop.
 */
#include <stdio.h>
#include <stdint.h>

enum TpVmPc {
    TP_LOAD       = 0,
    TP_INIT       = 1,
    TP_LOOP_CHECK = 2,
    TP_LOOP_BODY  = 3,
    TP_LOOP_INC   = 4,
    TP_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_treepath64_loop_target(uint64_t x) {
    int      idx = 0;
    int      n   = 0;
    uint64_t xx  = 0;
    uint64_t s   = 0;
    int      pc  = TP_LOAD;

    while (1) {
        if (pc == TP_LOAD) {
            xx = x;
            n  = (int)(x & 0x3Full) + 1;
            s  = 0ull;
            pc = TP_INIT;
        } else if (pc == TP_INIT) {
            idx = 0;
            pc = TP_LOOP_CHECK;
        } else if (pc == TP_LOOP_CHECK) {
            pc = (idx < n) ? TP_LOOP_BODY : TP_HALT;
        } else if (pc == TP_LOOP_BODY) {
            uint64_t bit = (xx >> idx) & 1ull;
            if (bit) {
                s = s * 3ull + 1ull;
            } else {
                s = s * 2ull;
            }
            pc = TP_LOOP_INC;
        } else if (pc == TP_LOOP_INC) {
            idx = idx + 1;
            pc = TP_LOOP_CHECK;
        } else if (pc == TP_HALT) {
            return s;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_treepath64(0xCAFE)=%llu vm_treepath64(0xFF)=%llu\n",
           (unsigned long long)vm_treepath64_loop_target(0xCAFEull),
           (unsigned long long)vm_treepath64_loop_target(0xFFull));
    return 0;
}
