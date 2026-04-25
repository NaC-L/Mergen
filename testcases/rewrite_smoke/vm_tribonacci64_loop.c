/* PC-state VM running a three-state Tribonacci-like recurrence on full
 * uint64_t.
 *   a = x;  b = ~x;  c = x ^ 0xCAFEBABE;
 *   for i in 0..n: { t = a + b + c; a = b; b = c; c = t; }
 *   return c;
 * Variable trip n = (x & 0xF) + 1.
 * Lift target: vm_tribonacci64_loop_target.
 *
 * Distinct from vm_fibonacci64_loop (two-state phi): exercises a
 * three-state phi chain on full i64 with three rolling slots advancing
 * one position per iteration.  Each new c uses all three previous
 * states; previous TEA-class compound cross-update failed but this
 * single-direction shift is the same shape as Fibonacci, just wider.
 */
#include <stdio.h>
#include <stdint.h>

enum TbVmPc {
    TB_LOAD       = 0,
    TB_INIT       = 1,
    TB_LOOP_CHECK = 2,
    TB_LOOP_BODY  = 3,
    TB_LOOP_INC   = 4,
    TB_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_tribonacci64_loop_target(uint64_t x) {
    int      idx = 0;
    int      n   = 0;
    uint64_t a   = 0;
    uint64_t b   = 0;
    uint64_t c   = 0;
    uint64_t t   = 0;
    int      pc  = TB_LOAD;

    while (1) {
        if (pc == TB_LOAD) {
            n = (int)(x & 0xFull) + 1;
            a = x;
            b = ~x;
            c = x ^ 0xCAFEBABEull;
            pc = TB_INIT;
        } else if (pc == TB_INIT) {
            idx = 0;
            pc = TB_LOOP_CHECK;
        } else if (pc == TB_LOOP_CHECK) {
            pc = (idx < n) ? TB_LOOP_BODY : TB_HALT;
        } else if (pc == TB_LOOP_BODY) {
            t = a + b + c;
            a = b;
            b = c;
            c = t;
            pc = TB_LOOP_INC;
        } else if (pc == TB_LOOP_INC) {
            idx = idx + 1;
            pc = TB_LOOP_CHECK;
        } else if (pc == TB_HALT) {
            return c;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_tribonacci64(0xCAFE)=%llu vm_tribonacci64(0xFF)=%llu\n",
           (unsigned long long)vm_tribonacci64_loop_target(0xCAFEull),
           (unsigned long long)vm_tribonacci64_loop_target(0xFFull));
    return 0;
}
