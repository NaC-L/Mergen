/* PC-state VM running a dynamic-amount ASHR (signed shift right) and
 * XOR-fold of the low byte over n = (x & 7) + 1 iterations:
 *
 *   n = (x & 7) + 1;
 *   r = 0;
 *   for (i = 0; i < n; i++) {
 *     int64_t sx = (int64_t)x >> i;       // dynamic ashr by i
 *     r = r ^ ((uint64_t)sx & 0xFF);
 *   }
 *   return r;
 *
 * Lift target: vm_dyn_ashr64_loop_target.
 *
 * Distinct from:
 *   - vm_bitfetch_window64_loop  (dynamic LSHR by counter)
 *   - vm_dynshl_pack64_loop      (dynamic SHL by counter)
 *   - vm_zigzag_step64_loop      (constant ashr-by-63)
 *
 * Completes the dynamic-shift trio (lshr / shl / ashr) for tests of
 * `ashr i64 x, %i` where %i is the loop-index phi.  Sign-extends the
 * input one position-shift further each iteration; the low byte
 * captures the moving signed window.  Negative inputs (high bit set)
 * fill with 1s, leading to different XOR patterns than unsigned shift.
 */
#include <stdio.h>
#include <stdint.h>

enum DaVmPc {
    DA_INIT_ALL = 0,
    DA_CHECK    = 1,
    DA_BODY     = 2,
    DA_INC      = 3,
    DA_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_dyn_ashr64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = DA_INIT_ALL;

    while (1) {
        if (pc == DA_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            r = 0ull;
            i = 0ull;
            pc = DA_CHECK;
        } else if (pc == DA_CHECK) {
            pc = (i < n) ? DA_BODY : DA_HALT;
        } else if (pc == DA_BODY) {
            int64_t sx = (int64_t)x >> (int)i;
            r = r ^ ((uint64_t)sx & 0xFFull);
            pc = DA_INC;
        } else if (pc == DA_INC) {
            i = i + 1ull;
            pc = DA_CHECK;
        } else if (pc == DA_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dyn_ashr64(0xDEADBEEF)=%llu\n",
           (unsigned long long)vm_dyn_ashr64_loop_target(0xDEADBEEFull));
    return 0;
}
