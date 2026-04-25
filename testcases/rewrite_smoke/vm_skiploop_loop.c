/* PC-state VM running a counted loop where odd iterations are skipped
 * (continue-style flow control), accumulating squares of even indices.
 * Lift target: vm_skiploop_loop_target.
 * Goal: cover a dispatcher transition that returns directly to the loop
 * header CHECK from the body's parity test, skipping the accumulator
 * update entirely on odd iterations.  Distinct from vm_dual_counter_loop
 * (always-increment one of two counters) and vm_zigzag_loop (always-write
 * with sign flip) because here some iterations contribute nothing at all.
 */
#include <stdio.h>

enum SkVmPc {
    SK_LOAD       = 0,
    SK_INIT       = 1,
    SK_CHECK      = 2,
    SK_TEST_PAR   = 3,
    SK_BODY_SQ    = 4,
    SK_BODY_ADD   = 5,
    SK_BODY_INC   = 6,
    SK_HALT       = 7,
};

__declspec(noinline)
int vm_skiploop_loop_target(int x) {
    int limit = 0;
    int idx   = 0;
    int sum   = 0;
    int sq    = 0;
    int pc    = SK_LOAD;

    while (1) {
        if (pc == SK_LOAD) {
            limit = x & 0xFF;
            idx = 0;
            sum = 0;
            pc = SK_INIT;
        } else if (pc == SK_INIT) {
            pc = SK_CHECK;
        } else if (pc == SK_CHECK) {
            pc = (idx < limit) ? SK_TEST_PAR : SK_HALT;
        } else if (pc == SK_TEST_PAR) {
            pc = ((idx & 1) != 0) ? SK_BODY_INC : SK_BODY_SQ;
        } else if (pc == SK_BODY_SQ) {
            sq = idx * idx;
            pc = SK_BODY_ADD;
        } else if (pc == SK_BODY_ADD) {
            sum = sum + sq;
            pc = SK_BODY_INC;
        } else if (pc == SK_BODY_INC) {
            idx = idx + 1;
            pc = SK_CHECK;
        } else if (pc == SK_HALT) {
            return sum;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_skiploop_loop(11)=%d vm_skiploop_loop(50)=%d\n",
           vm_skiploop_loop_target(11), vm_skiploop_loop_target(50));
    return 0;
}
