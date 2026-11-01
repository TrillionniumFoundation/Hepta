#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include "metrics.h"

#ifndef TARGET
#error TARGET must name the checked exported HIA function
#endif
extern uint8_t TARGET(size_t,size_t,size_t,size_t,size_t);

int main(int argc,char **argv) {
    struct rlimit core={0,0},cpu={2,2},memory={256*1024*1024,256*1024*1024};
    if (setrlimit(RLIMIT_CORE,&core)||setrlimit(RLIMIT_CPU,&cpu)||setrlimit(RLIMIT_AS,&memory)) return 71;
    if (argc!=6) return 72;
    size_t args[5];
    for (int i=0;i<5;++i) {
        char *end=0;
        unsigned long long n=strtoull(argv[i+1],&end,10);
        if (!end||*end||n>65536) return 73;
        args[i]=(size_t)n;
    }
    metrics_begin(0);
    uint8_t value=TARGET(args[0],args[1],args[2],args[3],args[4]);
    struct metrics result;
    metrics_end(&result);
    printf("{\"value\":%u,\"allocations\":%" PRIu64 ",\"frees\":%" PRIu64
           ",\"live\":%" PRIu64 ",\"live_requested\":%" PRIu64 ",\"accounting_errors\":%" PRIu64 "}\n",
           (unsigned)value,result.allocations,result.frees,result.live,result.live_requested,result.accounting_errors);
    return 0;
}
