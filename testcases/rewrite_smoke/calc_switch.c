/* Day-of-week name length: switch with 5 cases + default.
 * Lift target: calc_switch — multi-target branch resolution.
 * Expected IR: switch on symbolic input, resolving all case targets. */
#include <stdio.h>

__declspec(noinline)
int calc_switch(int day) {
    switch (day) {
    case 1: return 6;  /* Monday */
    case 2: return 7;  /* Tuesday */
    case 3: return 9;  /* Wednesday */
    case 4: return 8;  /* Thursday */
    case 5: return 6;  /* Friday */
    default: return 0; /* invalid */
    }
}

int main(void) {
    printf("switch(1)=%d switch(3)=%d switch(5)=%d switch(9)=%d\n",
           calc_switch(1), calc_switch(3), calc_switch(5), calc_switch(9));
    return 0;
}
