#include "tweak.h"

/* includes header2 */
const char *const req_hdr_fmt1 =
    "%s /prox1/%s%s HTTP/1.1\r\nHost: %s\r\n"
    "%s\r\n%s\r\nConnection: close\r\n\r\n";
/* no header2 */
const char *const req_hdr_fmt2 =
    "%s /prox1/%s%s HTTP/1.1\r\nHost: %s\r\n"
    "%s\r\nConnection: close\r\n\r\n";
