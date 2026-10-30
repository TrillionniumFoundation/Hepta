#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <time.h>
static uint64_t ns(clockid_t clock) { struct timespec t; if(clock_gettime(clock,&t)) exit(3); return (uint64_t)t.tv_sec*1000000000ULL+t.tv_nsec; }
static void mapped_image(const char *path, void *symbol) {
  int fd=-1, consumed=0;
  if(sscanf(path,"/proc/self/fd/%d%n",&fd,&consumed)!=1 || path[consumed] || fd<0) exit(6);
  struct stat file;
  int seals=F_SEAL_SEAL|F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_WRITE;
  if(fstat(fd,&file) || file.st_size<=0 || !S_ISREG(file.st_mode) || (fcntl(fd,F_GET_SEALS)&seals)!=seals) exit(6);
  FILE *maps=fopen("/proc/self/maps","r"); if(!maps) exit(6);
  char line[8192], permissions[5]; unsigned long start,end,offset;
  unsigned major_number,minor_number; unsigned long long inode; unsigned matches=0;
  uintptr_t address=(uintptr_t)symbol;
  while(fgets(line,sizeof(line),maps)) {
    if(sscanf(line,"%lx-%lx %4s %lx %x:%x %llu",&start,&end,permissions,&offset,&major_number,&minor_number,&inode)!=7) continue;
    if(address<start || address>=end) continue;
    if(strcmp(permissions,"r-xp") || major_number!=major(file.st_dev) || minor_number!=minor(file.st_dev) ||
       inode!=(unsigned long long)file.st_ino || (uint64_t)offset+address-start>=(uint64_t)file.st_size) exit(6);
    ++matches;
  }
  fclose(maps); if(matches!=1) exit(6);
}
int main(int argc,char **argv) {
  if(argc!=5) return 2;
  uint64_t n=strtoull(argv[2],0,10), calls=strtoull(argv[3],0,10), seed=strtoull(argv[4],0,10);
  if(n>65536 || calls==0 || calls>10000000 || seed>255) return 2;
  void *lib=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL); if(!lib) { fprintf(stderr,"%s",dlerror()); return 4; }
  uint64_t (*work)(size_t,uint32_t); *(void**)(&work)=dlsym(lib,"full_lifecycle"); if(!work) return 5;
  mapped_image(argv[1],(void*)work);
  uint64_t sum=0, start=ns(CLOCK_MONOTONIC), cpu=ns(CLOCK_PROCESS_CPUTIME_ID);
  for(uint64_t i=0;i<calls;i++) sum+=work(n,(uint32_t)((seed+i)&255));
  cpu=ns(CLOCK_PROCESS_CPUTIME_ID)-cpu; uint64_t elapsed=ns(CLOCK_MONOTONIC)-start;
  printf("{\"elapsed_ns\":%" PRIu64 ",\"process_cpu_ns\":%" PRIu64 ",\"checksum\":%" PRIu64 ",\"loaded_mapping_verified\":true}\n",elapsed,cpu,sum);
  dlclose(lib); return 0;
}
