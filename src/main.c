#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "wperf.h"
#include "report.h"

static const char DEFAULT_SSID[]={"LEDE"};
static const char DEFAULT_FILE[]={"/tmp/cadentwifi-report.txt"};
static const char DEFAULT_IFNAME[]={"wlan0"};
static const int  DEFUALT_FMTTYPE=0;

static inline void usage(char *prog, int ret)
{
   fprintf(stdout, "Usage: %s [option]\n", prog);
   fprintf(stdout, " -h            : print the debug message\n");
   fprintf(stdout, " -f <filename> : generate the report and copy to file\n");
   fprintf(stdout, " -i <intf name>: Interface name for prode the 2ghz/5ghz radio\n");
   fprintf(stdout, " -s <ssid name>: for monitor the specific ssid\n");
   exit(ret);
}

int main(int argc, char *argv[])
{
 int opt, ret;
 const char *ssid = DEFAULT_SSID;
 const char *reportfile = DEFAULT_FILE;
 const char *ifname = DEFAULT_IFNAME;
 int fmttype = DEFUALT_FMTTYPE;

 opterr=0 ; // ignore the error from getopt.
 while((opt = getopt(argc, argv, "hf:i:s:")) != -1)
 {
   switch(opt)
   {
     case 'f':
             reportfile = optarg;
             break;
     case 'i':
             ifname = optarg;
             break;
     case 's':
             ssid = optarg;
             break;
     case 'h':
             usage(argv[0], EXIT_SUCCESS);
             break;
     case ':':
             fprintf(stderr, "option requires argument %c\n", optopt);
             usage(argv[0], EXIT_FAILURE);
             break;
      case '?':
             fprintf(stderr, "unknown argument: %c\n", optopt);
             usage(argv[0], EXIT_FAILURE);
             break;
      default:
             fprintf(stderr, "unknown return from getopt: %c (0x%x)\n", opt, opt);
             usage(argv[0], EXIT_FAILURE);
             break;
   }
 }

 if(argv[optind]){
         fprintf(stderr, "unexpected argument: %s\n", argv[optind]);
         usage(argv[0], EXIT_FAILURE);
 }

 report_init(reportfile, fmttype);

 ret = wperf(ssid, ifname);
 if (ret == -1)
    return EXIT_FAILURE;

 sleep(100); //run this program for 100 sec
 return EXIT_SUCCESS;
}
