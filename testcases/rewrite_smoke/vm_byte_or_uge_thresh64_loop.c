/* PC-state VM that OR-accumulates bytes whose value is >= 0x80:
 *
 *   n = (x & 7) + 1;
 *   s = x; acc = 0;
 *   while (n) {
 *     uint64_t b = s & 0xFF;
 *     acc = acc | ((b >= 0x80) ? b : 0);
 *     s >>= 8;
 *     n--;
 *   }
 *   return acc;
 *
 * Lift target: vm_byte_or_uge_thresh64_loop_target.
 *
 * Predicate-gated OR accumulator at byte stride.  Tests select+or
 * fold (vs select+add and select+xor in sibling samples).
 */
#include <stdio.h>
#include <stdint.h>

enum BorVmPc {
    BOR_INIT_ALL = 0,
    BOR_CHECK    = 1,
    BOR_BODY     = 2,
    BOR_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_byte_or_uge_thresh64_loop_target(uint64_t x) {
    uint64_t n   = 0;
    uint64_t s   = 0;
    uint64_t acc = 0;
    int      pc  = BOR_INIT_ALL;

    while (1) {
        if (pc == BOR_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            acc = 0ull;
            pc = BOR_CHECK;
        } else if (pc == BOR_CHECK) {
            pc = (n > 0ull) ? BOR_BODY : BOR_HALT;
        } else if (pc == BOR_BODY) {
            uint64_t b = s & 0xFFull;
            acc = acc | ((b >= 0x80ull) ? b : 0ull);
            s = s >> 8;
            n = n - 1ull;
            pc = BOR_CHECK;
        } else if (pc == BOR_HALT) {
            return acc;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_byte_or_uge_thresh64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_byte_or_uge_thresh64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
