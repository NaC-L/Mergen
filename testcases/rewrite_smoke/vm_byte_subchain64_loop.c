/* PC-state VM that SUB-folds u8 bytes over n = (x & 7) + 1 iterations:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   while (n) {
 *     r = r - (s & 0xFF);
 *     s >>= 8;
 *     n--;
 *   }
 *   return r;
 *
 * Lift target: vm_byte_subchain64_loop_target.
 *
 * Distinct from:
 *   - vm_byte_addchain64_loop (ADD counterpart, same stride)
 *   - vm_word_subchain64_loop (16-bit word stride)
 *   - vm_subbyte_idx64_loop   (byte - counter at byte stride)
 *
 * Tests `sub i64` chain at 8-bit byte stride.  Result wraps below
 * zero into u64 modular space.  All-FF sums to -8*0xFF=2^64-2040.
 */
#include <stdio.h>
#include <stdint.h>

enum BsVmPc {
    BS_INIT_ALL = 0,
    BS_CHECK    = 1,
    BS_BODY     = 2,
    BS_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_byte_subchain64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    int      pc = BS_INIT_ALL;

    while (1) {
        if (pc == BS_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0ull;
            pc = BS_CHECK;
        } else if (pc == BS_CHECK) {
            pc = (n > 0ull) ? BS_BODY : BS_HALT;
        } else if (pc == BS_BODY) {
            r = r - (s & 0xFFull);
            s = s >> 8;
            n = n - 1ull;
            pc = BS_CHECK;
        } else if (pc == BS_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_byte_subchain64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_byte_subchain64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
