/* Symbolic trip-count counted loop.
 * Lift target: calc_sum_to_n — symbolic loop bound with a clamp.
 * Goal: preserve real loop structure (phi/backedge/compare), not constant-fold.
 */
#include <stdio.h>

__declspec(noinline)
int calc_sum_to_n(int n) {
    if (n > 32)
        n = 32;

    int sum = 0;
    for (int i = 0; i < n; i++)
        sum += i;

    return sum;
}

int main(void) {
    printf("sum_to_n(5)=%d sum_to_n(10)=%d\n",
           calc_sum_to_n(5), calc_sum_to_n(10));
    return 0;
}
