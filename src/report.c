#include <stdio.h>

void report_init(const char *filename, int fmttype)
{
 fprintf(stdout, "report created at %s with format type: %d\n", filename, fmttype);
 return;
}
