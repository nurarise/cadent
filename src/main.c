#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void usage(char *argv0, int ret)
{
   printf("Usage: %s [option]\n", argv0);
   printf(" -h: print the debug message\n");
   exit(ret);
}

int main(int argc, char *argv[])
{
 int opt;
 
 opterr=0 ; // igore the error from getopt.
 while((opt = getopt(argc, argv, ":h")) != -1)
 {
   switch(opt)
   {
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
 return EXIT_SUCCESS;
}
