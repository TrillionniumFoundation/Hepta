#define _POSIX_C_SOURCE 200809L
#include <dlfcn.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>

/* Fixed storage: no request-loop allocation or an input-dependent output buffer. */
#define MAX_CASES 1024
#define MAX_SAMPLES 1001
#define MAX_REPEATS 4096
static struct { int32_t a, b; int64_t expected[6]; } cases[MAX_CASES];
static uint64_t samples[MAX_SAMPLES];
typedef int64_t (*function_t)(int32_t, int32_t);
static const char *names[6] = {"service_stb_div_trunc", "service_stb_div_floor", "service_stb_div_eucl", "service_stb_mod_trunc", "service_stb_mod_floor", "service_stb_mod_eucl"};
_Static_assert(sizeof(int)==4 && INT_MIN==(-2147483647-1), "int32 host required");
static uint64_t ns(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) exit(20);
    return (uint64_t)t.tv_sec * UINT64_C(1000000000) + (uint64_t)t.tv_nsec;
}
static int integer(const char *text, int maximum, int *result) {
    char *end; errno = 0; long value = strtol(text, &end, 10);
    if (errno || end == text || *end || value < 1 || value > maximum) return 0;
    *result = (int)value; return 1;
}
static int request(function_t *functions, int i, uint64_t *checksum) {
    for (int f=0; f<6; ++f) {
        int64_t got = functions[f](cases[i].a, cases[i].b);
        if (got != cases[i].expected[f]) {
            fprintf(stderr,"mismatch case=%d function=%d a=%"PRId32" b=%"PRId32" actual=%"PRId64" expected=%"PRId64"\n",i,f,cases[i].a,cases[i].b,got,cases[i].expected[f]);
            return 0;
        }
        *checksum += (uint64_t)got; /* Defined modular accumulation in every arm. */
    }
    return 1;
}
int main(int argc, char **argv) {
    int count=0, n_samples, repeats; int64_t values[8]; char line[512];
    uint64_t checksum=0; function_t functions[6]; struct rusage usage;
    struct rlimit no_core={0,0};
    if (setrlimit(RLIMIT_CORE,&no_core) || argc != 5 ||
        !integer(argv[3],MAX_SAMPLES,&n_samples) || !integer(argv[4],MAX_REPEATS,&repeats)) return 2;
    FILE *input = fopen(argv[2],"r"); if (!input) return 3;
    while (fgets(line,sizeof(line),input)) {
        if (!strchr(line,'\n') && !feof(input)) return 4;
        char *cursor=line, *end;
        for(int k=0;k<8;++k) {
            errno=0; intmax_t value=strtoimax(cursor,&end,10);
            if(errno || end==cursor || value<INT64_MIN || value>INT64_MAX) return 4;
            values[k]=(int64_t)value; cursor=end;
        }
        while(isspace((unsigned char)*cursor)) ++cursor;
        if(*cursor || count==MAX_CASES || values[0]<INT32_MIN || values[0]>INT32_MAX ||
            values[1]<INT32_MIN || values[1]>INT32_MAX) return 4;
        cases[count].a=(int32_t)values[0]; cases[count].b=(int32_t)values[1];
        for(int f=0;f<6;++f) cases[count].expected[f]=values[f+2];
        ++count;
    }
    if(!count || ferror(input) || fclose(input)) return 5;
    uint64_t cold_start=ns();
    void *library=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL); if (!library) {fprintf(stderr,"%s\n",dlerror()); return 6;}
    for(int f=0;f<6;++f) {
        void *symbol=dlsym(library,names[f]);
        if(!symbol || sizeof(symbol)!=sizeof(functions[f])) return 7;
        memcpy(&functions[f],&symbol,sizeof(symbol));
    }
    uint64_t loaded=ns();
    if(!request(functions,0,&checksum)) return 8;
    uint64_t delivered=ns();
    checksum=0;
    /* Exactly one unmeasured warmup pass is paid and checked. */
    for(int i=0;i<count;++i) if(!request(functions,i,&checksum)) return 8;
    checksum=0;
    for(int sample=0;sample<n_samples;++sample) {
        uint64_t start=ns();
        for(int r=0;r<repeats;++r) for(int i=0;i<count;++i)
            if(!request(functions,i,&checksum)) return 8;
        samples[sample]=ns()-start;
    }
    if(getrusage(RUSAGE_SELF,&usage)) return 9;
    if(dlclose(library)) return 10;
    printf("{\"cases\":%d,\"samples\":%d,\"repeats\":%d,\"calls\":%"PRIu64",\"checksum\":%"PRIu64",\"load_ns\":%"PRIu64",\"first_request_ns\":%"PRIu64",\"cold_delivery_ns\":%"PRIu64",\"peak_rss_kib\":%ld,\"batch_ns\":[", count,n_samples,repeats,(uint64_t)count*n_samples*repeats*6,checksum,loaded-cold_start,delivered-loaded,delivered-cold_start,usage.ru_maxrss);
    for(int i=0;i<n_samples;++i) printf("%s%"PRIu64,i?",":"",samples[i]);
    puts("]}"); return 0;
}
