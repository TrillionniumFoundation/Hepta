#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>
#include <inttypes.h>
#include <errno.h>
#include <limits.h>
typedef uint64_t (*Batch)(const int32_t*,int32_t*,size_t,int32_t,uint32_t);
static uint64_t ns(void){struct timespec ts;if(clock_gettime(CLOCK_MONOTONIC,&ts))abort();return (uint64_t)ts.tv_sec*1000000000ull+ts.tv_nsec;}
static uint32_t next(uint32_t*state){uint32_t x=*state;x^=x<<13;x^=x>>17;x^=x<<5;return *state=x;}
static uint64_t parse(const char*s){char*end=0;errno=0;unsigned long long v=strtoull(s,&end,10);if(errno||end==s||*end)exit(2);return v;}
int main(int argc,char**argv){
 if(argc==4 && strcmp(argv[1],"--trap")==0){
  void*h=dlopen(argv[2],RTLD_NOW|RTLD_LOCAL);if(!h){fprintf(stderr,"%s\n",dlerror());return 3;}
  int32_t(*f)(int32_t,int32_t)=(int32_t(*)(int32_t,int32_t))dlsym(h,"c_stb_div_trunc");if(!f)return 4;
  fputs("ENTERED_HIA\n",stdout);fflush(stdout);
  return f(strcmp(argv[3],"zero")==0?7:INT32_MIN,strcmp(argv[3],"zero")==0?0:-1);
 }
 if(argc!=7)return 2;
 uint32_t seed=(uint32_t)parse(argv[2]);int32_t divisor=(int32_t)parse(argv[3]);
 size_t count=(size_t)parse(argv[4]);uint32_t rounds=(uint32_t)parse(argv[5]);uint32_t warmup=(uint32_t)parse(argv[6]);
 if(!seed||divisor<2||count<32||count>1048576||!rounds||rounds>4194304||warmup>8192)return 2;
 int32_t*input=malloc(count*sizeof(*input));int32_t*output=malloc(count*sizeof(*output));if(!input||!output)return 6;
 for(size_t i=0;i<count;i++)input[i]=(int32_t)next(&seed);
 input[0]=INT32_MIN;input[1]=INT32_MAX;input[2]=-1;input[3]=0;input[4]=1;
 uint64_t load_begin=ns();void*handle=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL);if(!handle){fprintf(stderr,"%s\n",dlerror());return 3;}
 Batch f=(Batch)dlsym(handle,"batch");if(!f)return 4;uint64_t load_ns=ns()-load_begin;
 uint64_t begin=ns();if(warmup)f(input,output,count,divisor,warmup);uint64_t warmup_ns=ns()-begin;
 begin=ns();uint64_t checksum=f(input,output,count,divisor,rounds);uint64_t elapsed=ns()-begin;
 begin=ns();uint64_t one_period=0,expected=0;for(size_t i=0;i<count;i++){int32_t q=input[i]/divisor;if(q!=output[i]){fprintf(stderr,"mismatch %zu %d %d\n",i,q,output[i]);return 5;}one_period+=(uint32_t)q;}
 expected=one_period*(rounds/count);for(uint32_t r=0;r<rounds%count;r++)expected+=(uint32_t)(input[r]/divisor);
 if(expected!=checksum){fprintf(stderr,"checksum mismatch\n");return 5;}uint64_t observation_ns=ns()-begin;
 struct rusage ru;if(getrusage(RUSAGE_SELF,&ru))return 7;
 begin=ns();if(dlclose(handle))return 8;free(input);free(output);uint64_t cleanup_ns=ns()-begin;
 printf("{\"schema\":\"hepta.stb-context-host.v1\",\"count\":%zu,\"rounds\":%u,\"divisor\":%d,\"calls\":%"PRIu64",\"checksum\":%"PRIu64",\"wall_ns\":%"PRIu64",\"load_ns\":%"PRIu64",\"warmup_ns\":%"PRIu64",\"observation_ns\":%"PRIu64",\"cleanup_ns\":%"PRIu64",\"peak_rss_kib\":%ld,\"correct\":true}\n",count,rounds,divisor,(uint64_t)count*rounds,checksum,elapsed,load_ns,warmup_ns,observation_ns,cleanup_ns,ru.ru_maxrss);
 return 0;
}
