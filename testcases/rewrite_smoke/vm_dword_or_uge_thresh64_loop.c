/* PC-state VM that OR-accumulates u32 dwords >= 0x80000000:
 *
 *   n = (x & 1) + 1;
 *   s = x; acc = 0;
 *   while (n) {
 *     uint64_t d = s & 0xFFFFFFFF;
 *     acc = acc | ((d >= 0x80000000) ? d : 0);
 *     s >>= 32;
 *     n--;
 *   }
 *   return acc;
 *
 * Lift target: vm_dword_or_uge_thresh64_loop_target.
 *
 * Predicate-gated OR accumulator at u32 stride.
 */
#include <stdio.h>
#include <stdint.h>

enum DorVmPc {
    DOR_INIT_ALL = 0,
    DOR_CHECK    = 1,
    DOR_BODY     = 2,
    DOR_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_dword_or_uge_thresh64_loop_target(uint64_t x) {
    uint64_t n   = 0;
    uint64_t s   = 0;
    uint64_t acc = 0;
    int      pc  = DOR_INIT_ALL;

    while (1) {
        if (pc == DOR_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            acc = 0ull;
            pc = DOR_CHECK;
        } else if (pc == DOR_CHECK) {
            pc = (n > 0ull) ? DOR_BODY : DOR_HALT;
        } else if (pc == DOR_BODY) {
            uint64_t d = s & 0xFFFFFFFFull;
            acc = acc | ((d >= 0x80000000ull) ? d : 0ull);
            s = s >> 32;
            n = n - 1ull;
            pc = DOR_CHECK;
        } else if (pc == DOR_HALT) {
            return acc;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dword_or_uge_thresh64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_dword_or_uge_thresh64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
