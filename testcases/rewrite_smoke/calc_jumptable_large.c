/* Large jump table test: 16 dense cases compiled with /O2.
 * Tests that the lifter handles tables larger than the existing 4/8/10
 * entry tests and produces correct dispatch for all 16 values.
 *
 * Return values are deliberately irregular (no arithmetic pattern) so
 * the compiler cannot fold the switch into a formula.
 *
 * Lift target: calc_jumptable_large
 * NOTE: Filename contains "_jumptable" so build_samples.cmd compiles
 * with /O2 (required for real jump table generation). */

#include <stdio.h>

__declspec(noinline)
int calc_jumptable_large(int op) {
    switch (op) {
    case 0:  return 7;
    case 1:  return 42;
    case 2:  return 13;
    case 3:  return 99;
    case 4:  return 256;
    case 5:  return 31;
    case 6:  return 1024;
    case 7:  return 3;
    case 8:  return 777;
    case 9:  return 55;
    case 10: return 404;
    case 11: return 1337;
    case 12: return 88;
    case 13: return 500;
    case 14: return 65535;
    case 15: return 21;
    default: return -1;
    }
}

int main(void) {
    printf("jt(0)=%d jt(7)=%d jt(15)=%d jt(99)=%d\n",
           calc_jumptable_large(0), calc_jumptable_large(7),
           calc_jumptable_large(15), calc_jumptable_large(99));
    return 0;
}
