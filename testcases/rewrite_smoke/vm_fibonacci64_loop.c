/* PC-state VM running a Fibonacci-shape recurrence on full uint64_t.
 *   a = x;  b = x ^ K_INIT;
 *   for i in 0..n: t = a + b; a = b; b = t;
 * Where n = (x & 0x3F) + 1 and K_INIT = 0xCAFEBABEDEADBEEF.
 * Returns final b as full uint64_t.
 * Lift target: vm_fibonacci64_loop_target.
 *
 * Distinct from vm_fibonacci_loop (i32 fib).  Both initial values and the
 * trip count derive from the full input; the recurrence wraps mod 2^64.
 */
#include <stdio.h>
#include <stdint.h>

enum F64VmPc {
    F64_LOAD       = 0,
    F64_INIT       = 1,
    F64_LOOP_CHECK = 2,
    F64_LOOP_BODY  = 3,
    F64_LOOP_INC   = 4,
    F64_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_fibonacci64_loop_target(uint64_t x) {
    int      idx = 0;
    int      n   = 0;
    uint64_t a   = 0;
    uint64_t b   = 0;
    uint64_t t   = 0;
    int      pc  = F64_LOAD;

    while (1) {
        if (pc == F64_LOAD) {
            n = (int)(x & 0x3Full) + 1;
            a = x;
            b = x ^ 0xCAFEBABEDEADBEEFull;
            pc = F64_INIT;
        } else if (pc == F64_INIT) {
            idx = 0;
            pc = F64_LOOP_CHECK;
        } else if (pc == F64_LOOP_CHECK) {
            pc = (idx < n) ? F64_LOOP_BODY : F64_HALT;
        } else if (pc == F64_LOOP_BODY) {
            t = a + b;
            a = b;
            b = t;
            pc = F64_LOOP_INC;
        } else if (pc == F64_LOOP_INC) {
            idx = idx + 1;
            pc = F64_LOOP_CHECK;
        } else if (pc == F64_HALT) {
            return b;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_fib64(0xCAFE)=0x%llx vm_fib64(0xFF)=0x%llx\n",
           (unsigned long long)vm_fibonacci64_loop_target(0xCAFEull),
           (unsigned long long)vm_fibonacci64_loop_target(0xFFull));
    return 0;
}
