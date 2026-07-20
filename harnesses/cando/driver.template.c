/* cando-style function-level differential driver — C ORACLE side.
 *
 * Build this against the C library under port; the Rust driver
 * (driver.template.rs) is the same protocol built against the Rust port. The
 * harness (cando_diff.py) runs both over a vector suite and diffs, so each
 * exported function is tested individually — the differential a *library* needs,
 * where diff_run.py (whole-program argv->stdout) does not fit.
 *
 * Protocol:
 *   argv[1] = function name, argv[2..] = string args, optional stdin.
 *   Print the function's result CANONICALLY to stdout — the SAME textual format
 *   the Rust driver prints (fix byte order, radix, separators, trailing newline
 *   on both sides, or you manufacture a divergence). Return 0 on success,
 *   nonzero on error / unsupported function. A nonzero exit makes cando_diff
 *   treat the vector as a failed C baseline (a vector must pass on C before it
 *   can judge Rust) unless the suite is run with --allow-oracle-error.
 *
 * Keep the driver THIN: parse args, call ONE library function, serialize the
 * result. All the logic under test lives in the library, not here.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* #include "yourlib.h" */

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <func> [args...]\n", argv[0]);
        return 2;
    }
    const char *func = argv[1];

    /* One branch per exported function under test. Replace with the real calls. */
    if (strcmp(func, "__EXAMPLE__checksum") == 0) {
        /* unsigned r = yourlib_checksum((const unsigned char *)argv[2], strlen(argv[2])); */
        /* printf("%u\n", r); */
        return 0;
    }
    if (strcmp(func, "__EXAMPLE__parse") == 0) {
        /* int rc = yourlib_parse(argv[2]); */
        /* printf("%d\n", rc); */
        return 0;
    }

    fprintf(stderr, "unsupported function: %s\n", func);
    return 4;
}
