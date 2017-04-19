#include <stdio.h>
#include <stdlib.h>

int wperf(const char *ssid, const char *ifname)
{
  fprintf(stdout, "wperf: for ssid:%s over ifname: %s\n", ssid, ifname);
  return 0;
}
