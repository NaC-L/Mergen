/* PC-state VM running a dynamic-amount ASHR (signed shift right) and
 * XOR-fold of the low u16 word over n = (x & 7) + 1 iterations:
 *
 *   n = (x & 7) + 1;
 *   r = 0;
 *   for (i = 0; i < n; i++) {
 *     int64_t sx = (int64_t)x >> i;       // dynamic ashr by i
 *     r = r ^ ((uint64_t)sx & 0xFFFF);
 *   }
 *   return r;
 *
 * Lift target: vm_dyn_ashr_word64_loop_target.
 *
 * Distinct from:
 *   - vm_dyn_ashr64_loop (8-bit window)
 *   - vm_bitfetch_window64_loop (1-bit window)
 *
 * Wider 16-bit window of the moving signed shift; word-mask captures
 * more of the running ashr output per iter so XOR pattern differs from
 * the byte-window variant.
 */
#include <stdio.h>
#include <stdint.h>

enum DawVmPc {
    DAW3_INIT_ALL = 0,
    DAW3_CHECK    = 1,
    DAW3_BODY     = 2,
    DAW3_INC      = 3,
    DAW3_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_dyn_ashr_word64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = DAW3_INIT_ALL;

    while (1) {
        if (pc == DAW3_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            r = 0ull;
            i = 0ull;
            pc = DAW3_CHECK;
        } else if (pc == DAW3_CHECK) {
            pc = (i < n) ? DAW3_BODY : DAW3_HALT;
        } else if (pc == DAW3_BODY) {
            int64_t sx = (int64_t)x >> (int)i;
            r = r ^ ((uint64_t)sx & 0xFFFFull);
            pc = DAW3_INC;
        } else if (pc == DAW3_INC) {
            i = i + 1ull;
            pc = DAW3_CHECK;
        } else if (pc == DAW3_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dyn_ashr_word64(0xDEADBEEF)=%llu\n",
           (unsigned long long)vm_dyn_ashr_word64_loop_target(0xDEADBEEFull));
    return 0;
}
