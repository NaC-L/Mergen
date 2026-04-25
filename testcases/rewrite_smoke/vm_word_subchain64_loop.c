/* PC-state VM that SUB-folds u16 words over n = (x & 3) + 1 iterations:
 *
 *   n = (x & 3) + 1;
 *   s = x; r = 0;
 *   while (n) {
 *     r = r - (s & 0xFFFF);
 *     s >>= 16;
 *     n--;
 *   }
 *   return r;
 *
 * Lift target: vm_word_subchain64_loop_target.
 *
 * Distinct from:
 *   - vm_word_addchain64_loop (ADD counterpart, same stride)
 *   - vm_subbyte_idx64_loop   (byte * counter SUB, 8-bit stride)
 *   - vm_word_orfold64_loop   (OR fold)
 *
 * Tests `sub i64` chain at 16-bit word stride.  Result wraps below
 * zero into u64 modular space.  All-FF sums to -4*0xFFFF=2^64-262140.
 */
#include <stdio.h>
#include <stdint.h>

enum WsVmPc {
    WS_INIT_ALL = 0,
    WS_CHECK    = 1,
    WS_BODY     = 2,
    WS_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_word_subchain64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    int      pc = WS_INIT_ALL;

    while (1) {
        if (pc == WS_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            r = 0ull;
            pc = WS_CHECK;
        } else if (pc == WS_CHECK) {
            pc = (n > 0ull) ? WS_BODY : WS_HALT;
        } else if (pc == WS_BODY) {
            r = r - (s & 0xFFFFull);
            s = s >> 16;
            n = n - 1ull;
            pc = WS_CHECK;
        } else if (pc == WS_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_word_subchain64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_word_subchain64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
