/* Grade calculator: cascading if/else on symbolic input (ECX).
 * Lift target: calc_grade — no loops, pure branching.
 * Expected IR: chain of icmp + select on the symbolic argument. */
#include <stdio.h>

__declspec(noinline)
int calc_grade(int score) {
    if (score >= 90) return 4;   /* A */
    if (score >= 80) return 3;   /* B */
    if (score >= 70) return 2;   /* C */
    if (score >= 60) return 1;   /* D */
    return 0;                    /* F */
}

int main(void) {
    printf("grade(95)=%d grade(82)=%d grade(55)=%d\n",
           calc_grade(95), calc_grade(82), calc_grade(55));
    return 0;
}
