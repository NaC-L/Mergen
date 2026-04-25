/* PC-state VM that counts bytes equal to the first byte:
 *
 *   n = (x & 7) + 1;
 *   s = x; first = s & 0xFF; cnt = 0;
 *   while (n) {
 *     uint64_t b = s & 0xFF;
 *     cnt = cnt + ((b == first) ? 1 : 0);
 *     s >>= 8;
 *     n--;
 *   }
 *   return cnt;
 *
 * Lift target: vm_byte_eq_first_count64_loop_target.
 *
 * Distinct from:
 *   - vm_branchy_loop (conditional add, no stable reference)
 *   - vm_byterange64_loop (min/max not equality count)
 *   - vm_bytematch64_loop (byte == constant key)
 *
 * Tests `icmp eq` + zext-i1 + add chain inside dispatcher loop.
 * 4 stateful slots (n, s, first, cnt) - within the working budget.
 * All-FF: every byte matches first -> cnt=8.
 */
#include <stdio.h>
#include <stdint.h>

enum BeVmPc {
    BE_INIT_ALL = 0,
    BE_CHECK    = 1,
    BE_BODY     = 2,
    BE_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_byte_eq_first_count64_loop_target(uint64_t x) {
    uint64_t n     = 0;
    uint64_t s     = 0;
    uint64_t first = 0;
    uint64_t cnt   = 0;
    int      pc    = BE_INIT_ALL;

    while (1) {
        if (pc == BE_INIT_ALL) {
            n     = (x & 7ull) + 1ull;
            s     = x;
            first = x & 0xFFull;
            cnt   = 0ull;
            pc = BE_CHECK;
        } else if (pc == BE_CHECK) {
            pc = (n > 0ull) ? BE_BODY : BE_HALT;
        } else if (pc == BE_BODY) {
            uint64_t b = s & 0xFFull;
            cnt = cnt + ((b == first) ? 1ull : 0ull);
            s = s >> 8;
            n = n - 1ull;
            pc = BE_CHECK;
        } else if (pc == BE_HALT) {
            return cnt;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_byte_eq_first_count64(0xAAAAAAAAAAAAAAAA)=%llu\n",
           (unsigned long long)vm_byte_eq_first_count64_loop_target(0xAAAAAAAAAAAAAAAAull));
    return 0;
}
