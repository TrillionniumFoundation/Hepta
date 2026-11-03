#define _POSIX_C_SOURCE 200809L
#include <dlfcn.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
static uint64_t ns(clockid_t clock) { struct timespec t; if (clock_gettime(clock,&t)) exit(3); return (uint64_t)t.tv_sec*1000000000ULL+t.tv_nsec; }
int main(int argc,char **argv) {
  if(argc!=5) return 2;
  uint64_t n=strtoull(argv[2],0,10), calls=strtoull(argv[3],0,10), seed=strtoull(argv[4],0,10);
  if(n>4096 || calls==0 || calls>10000000 || seed>255) return 2;
  void *lib=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL); if(!lib) { fprintf(stderr,"%s",dlerror()); return 4; }
  uint64_t (*work)(uint64_t,uint64_t); *(void**)(&work)=dlsym(lib,"work"); if(!work) return 5;
  uint64_t sum=0, start=ns(CLOCK_MONOTONIC), cpu=ns(CLOCK_PROCESS_CPUTIME_ID);
  for(uint64_t i=0;i<calls;i++) sum+=work(n,(seed+i)&255);
  cpu=ns(CLOCK_PROCESS_CPUTIME_ID)-cpu; uint64_t elapsed=ns(CLOCK_MONOTONIC)-start;
  printf("{\"elapsed_ns\":%" PRIu64 ",\"process_cpu_ns\":%" PRIu64 ",\"checksum\":%" PRIu64 "}\n",elapsed,cpu,sum);
  dlclose(lib); return 0;
}
