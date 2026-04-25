/* PC-state VM that fills an unsigned-short[8] stack array and accumulates
 * via zero-extending loads.
 * Lift target: vm_ushort_array_loop_target.
 * Goal: cover an unsigned-i16-element stack array (zext i16 -> i32 at use
 * sites), distinct from the signed `short[]` variant which exercises
 * sext i16.  Symbolic seed keeps the per-element add from being folded.
 */
#include <stdio.h>

enum UaVmPc {
    UA_LOAD       = 0,
    UA_INIT_FILL  = 1,
    UA_FILL_CHECK = 2,
    UA_FILL_BODY  = 3,
    UA_FILL_INC   = 4,
    UA_INIT_SUM   = 5,
    UA_SUM_CHECK  = 6,
    UA_SUM_BODY   = 7,
    UA_SUM_INC    = 8,
    UA_HALT       = 9,
};

__declspec(noinline)
unsigned int vm_ushort_array_loop_target(unsigned int x) {
    unsigned short buf[8];
    int idx           = 0;
    unsigned int sum  = 0;
    unsigned short seed = 0;
    int pc            = UA_LOAD;

    while (1) {
        if (pc == UA_LOAD) {
            seed = (unsigned short)(x & 0xFFFFu);
            pc = UA_INIT_FILL;
        } else if (pc == UA_INIT_FILL) {
            idx = 0;
            pc = UA_FILL_CHECK;
        } else if (pc == UA_FILL_CHECK) {
            pc = (idx < 8) ? UA_FILL_BODY : UA_INIT_SUM;
        } else if (pc == UA_FILL_BODY) {
            buf[idx] = (unsigned short)((unsigned int)seed + (unsigned int)idx * 100u);
            pc = UA_FILL_INC;
        } else if (pc == UA_FILL_INC) {
            idx = idx + 1;
            pc = UA_FILL_CHECK;
        } else if (pc == UA_INIT_SUM) {
            idx = 0;
            pc = UA_SUM_CHECK;
        } else if (pc == UA_SUM_CHECK) {
            pc = (idx < 8) ? UA_SUM_BODY : UA_HALT;
        } else if (pc == UA_SUM_BODY) {
            sum = sum + (unsigned int)buf[idx];
            pc = UA_SUM_INC;
        } else if (pc == UA_SUM_INC) {
            idx = idx + 1;
            pc = UA_SUM_CHECK;
        } else if (pc == UA_HALT) {
            return sum;
        } else {
            return 0xFFFFFFFFu;
        }
    }
}

int main(void) {
    printf("vm_ushort_array_loop(0xFDE8)=%u vm_ushort_array_loop(0xCAFE)=%u\n",
           vm_ushort_array_loop_target(0xFDE8u),
           vm_ushort_array_loop_target(0xCAFEu));
    return 0;
}
