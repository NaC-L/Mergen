/* PC-state VM that ORs bytes and counter values into a single
 * accumulator over n = (x & 7) + 1 iterations:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = r | ((s & 0xFF) | (i + 1));   // OR-accumulator
 *     s >>= 8;
 *   }
 *   return r;
 *
 * Lift target: vm_orsum_byte_idx64_loop_target.
 *
 * Distinct from:
 *   - vm_xormul_byte_idx64_loop  (XOR fold of byte * counter)
 *   - vm_andsum_byte_idx64_loop  (AND of byte with counter, ADD-folded)
 *   - vm_uintadd_byte_idx64_loop (ADD of byte * counter)
 *
 * Tests `or i64` of zext-byte with phi-tracked counter (i+1) folded
 * via OR-accumulator.  Unlike XOR which can cancel, OR is monotone
 * (only sets bits).  Counter values 1..8 contribute fixed low bits
 * regardless of byte content.
 */
#include <stdio.h>
#include <stdint.h>

enum OsVmPc {
    OS_INIT_ALL = 0,
    OS_CHECK    = 1,
    OS_BODY     = 2,
    OS_INC      = 3,
    OS_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_orsum_byte_idx64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = OS_INIT_ALL;

    while (1) {
        if (pc == OS_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = OS_CHECK;
        } else if (pc == OS_CHECK) {
            pc = (i < n) ? OS_BODY : OS_HALT;
        } else if (pc == OS_BODY) {
            r = r | ((s & 0xFFull) | (i + 1ull));
            s = s >> 8;
            pc = OS_INC;
        } else if (pc == OS_INC) {
            i = i + 1ull;
            pc = OS_CHECK;
        } else if (pc == OS_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_orsum_byte_idx64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_orsum_byte_idx64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
