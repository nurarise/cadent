#ifndef __REPORT_H__
#define __REPORT_H__

#ifdef __cplusplus
extern "C" {
#endif
void report_init(const char *filename, const int fmttype);
void report_show(void);
int report_write(char *data);

#ifdef __cplusplus
}
#endif
#endif //#ifndef __REPORT_H__
