/* PC-state VM with DATA-DEPENDENT arithmetic right-shift amount:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = x;
 *   for (i = 0; i < n; i++) {
 *     uint64_t b = s & 0xFF;
 *     int amt = (int)(b & 7);
 *     r = (uint64_t)((int64_t)r >> amt) + b;   // ashr by byte amount
 *     s >>= 8;
 *   }
 *   return r;
 *
 * Lift target: vm_data_ashr64_loop_target.
 *
 * Distinct from:
 *   - vm_byteshl_data64_loop  (data-dependent SHL)
 *   - vm_data_lshr64_loop     (data-dependent LSHR)
 *   - vm_dyn_ashr64_loop      (ashr by loop counter, NOT byte data)
 *
 * Completes the data-dependent shift trio (shl / lshr / ashr).
 * Sign-extending right-shift by an amount that comes from the byte
 * stream propagates the high bit of the running r through iterations,
 * producing different fills than lshr for high-bit-set states.
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
uint64_t vm_data_ashr64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = DA_INIT_ALL;

    while (1) {
        if (pc == DA_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = x;
            i = 0ull;
            pc = DA_CHECK;
        } else if (pc == DA_CHECK) {
            pc = (i < n) ? DA_BODY : DA_HALT;
        } else if (pc == DA_BODY) {
            uint64_t b   = s & 0xFFull;
            int      amt = (int)(b & 7ull);
            r = (uint64_t)((int64_t)r >> amt) + b;
            s = s >> 8;
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
    printf("vm_data_ashr64(0xDEADBEEF)=%llu\n",
           (unsigned long long)vm_data_ashr64_loop_target(0xDEADBEEFull));
    return 0;
}
