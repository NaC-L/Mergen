/* PC-state VM running an i64 factorial.
 *   n = (x & 0x1F) + 1;     // 1..32
 *   r = 1;
 *   for i in 1..n+1: r = r * i;
 *   return r;     // wraps mod 2^64 for n >= 21
 * Lift target: vm_factorial64_loop_target.
 *
 * Distinct from vm_factorial_loop (i32 factorial): exercises i64 mul
 * inside a variable-trip loop with deliberate wrap (21! through 32!
 * exceed u64 range and wrap mod 2^64).
 */
#include <stdio.h>
#include <stdint.h>

enum FaVmPc {
    FA_LOAD       = 0,
    FA_INIT       = 1,
    FA_LOOP_CHECK = 2,
    FA_LOOP_BODY  = 3,
    FA_LOOP_INC   = 4,
    FA_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_factorial64_loop_target(uint64_t x) {
    int      idx = 0;
    int      n   = 0;
    uint64_t r   = 0;
    int      pc  = FA_LOAD;

    while (1) {
        if (pc == FA_LOAD) {
            n = (int)(x & 0x1Full) + 1;
            r = 1ull;
            pc = FA_INIT;
        } else if (pc == FA_INIT) {
            idx = 1;
            pc = FA_LOOP_CHECK;
        } else if (pc == FA_LOOP_CHECK) {
            pc = (idx <= n) ? FA_LOOP_BODY : FA_HALT;
        } else if (pc == FA_LOOP_BODY) {
            r = r * (uint64_t)idx;
            pc = FA_LOOP_INC;
        } else if (pc == FA_LOOP_INC) {
            idx = idx + 1;
            pc = FA_LOOP_CHECK;
        } else if (pc == FA_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_factorial64(20)=%llu vm_factorial64(21)=%llu\n",
           (unsigned long long)vm_factorial64_loop_target(19ull),  /* n=20 */
           (unsigned long long)vm_factorial64_loop_target(20ull)); /* n=21 wraps */
    return 0;
}
