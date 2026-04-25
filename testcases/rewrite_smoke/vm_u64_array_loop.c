/* PC-state VM that fills a uint64_t[4] stack array with full 64-bit
 * values and accumulates them, returning the low 32 bits.
 * Lift target: vm_u64_array_loop_target.
 * Goal: cover an i64-element stack array (distinct from scalar-i64 cases
 * such as vm_int64_loop / vm_shift64_loop).  Symbolic seed and large i64
 * constants keep the lifter from collapsing the multiplies, and the final
 * 32-bit return matches the lifter's i64->i32 narrowing convention.
 */
#include <stdio.h>
#include <stdint.h>

enum U64VmPc {
    U64_LOAD       = 0,
    U64_INIT_FILL  = 1,
    U64_FILL_CHECK = 2,
    U64_FILL_BODY  = 3,
    U64_FILL_INC   = 4,
    U64_INIT_SUM   = 5,
    U64_SUM_CHECK  = 6,
    U64_SUM_BODY   = 7,
    U64_SUM_INC    = 8,
    U64_HALT       = 9,
};

__declspec(noinline)
unsigned int vm_u64_array_loop_target(uint64_t x) {
    uint64_t buf[4];
    int idx        = 0;
    uint64_t sum   = 0;
    uint64_t seed  = 0;
    int pc         = U64_LOAD;

    while (1) {
        if (pc == U64_LOAD) {
            seed = x;
            pc = U64_INIT_FILL;
        } else if (pc == U64_INIT_FILL) {
            idx = 0;
            pc = U64_FILL_CHECK;
        } else if (pc == U64_FILL_CHECK) {
            pc = (idx < 4) ? U64_FILL_BODY : U64_INIT_SUM;
        } else if (pc == U64_FILL_BODY) {
            buf[idx] = seed * (uint64_t)(idx + 1) + (uint64_t)idx * 0x100000001ull;
            pc = U64_FILL_INC;
        } else if (pc == U64_FILL_INC) {
            idx = idx + 1;
            pc = U64_FILL_CHECK;
        } else if (pc == U64_INIT_SUM) {
            idx = 0;
            pc = U64_SUM_CHECK;
        } else if (pc == U64_SUM_CHECK) {
            pc = (idx < 4) ? U64_SUM_BODY : U64_HALT;
        } else if (pc == U64_SUM_BODY) {
            sum = sum + buf[idx];
            pc = U64_SUM_INC;
        } else if (pc == U64_SUM_INC) {
            idx = idx + 1;
            pc = U64_SUM_CHECK;
        } else if (pc == U64_HALT) {
            return (unsigned int)(sum & 0xFFFFFFFFu);
        } else {
            return 0xFFFFFFFFu;
        }
    }
}

int main(void) {
    printf("vm_u64_array_loop(0xCAFEBABE)=%u vm_u64_array_loop(0xFFFFFFFFFFFFFFFF)=%u\n",
           vm_u64_array_loop_target(0xCAFEBABEull),
           vm_u64_array_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
