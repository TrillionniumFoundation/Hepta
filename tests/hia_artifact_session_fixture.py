"""Direct verified Core fixtures and unchanged foreign child checksum oracle.

The driver and arithmetic oracle are historical test controls, not HIA-native
runtime claims. No deleted high-level parser/lowering or campaign is imported.
"""
import json
from pathlib import Path
from hepta.hia_program import verify_program
MODULES = ("byte_sum", "packet_xor")
DRIVER = '#define _GNU_SOURCE\n#include <dlfcn.h>\n#include <fcntl.h>\n#include <inttypes.h>\n#include <stdint.h>\n#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n#include <sys/stat.h>\n#include <sys/sysmacros.h>\n#include <time.h>\nstatic uint64_t ns(clockid_t clock) { struct timespec t; if(clock_gettime(clock,&t)) exit(3); return (uint64_t)t.tv_sec*1000000000ULL+t.tv_nsec; }\nstatic void mapped_image(const char *path, void *symbol) {\n  int fd=-1, consumed=0;\n  if(sscanf(path,"/proc/self/fd/%d%n",&fd,&consumed)!=1 || path[consumed] || fd<0) exit(6);\n  struct stat file;\n  int seals=F_SEAL_SEAL|F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_WRITE;\n  if(fstat(fd,&file) || file.st_size<=0 || !S_ISREG(file.st_mode) || (fcntl(fd,F_GET_SEALS)&seals)!=seals) exit(6);\n  FILE *maps=fopen("/proc/self/maps","r"); if(!maps) exit(6);\n  char line[8192], permissions[5]; unsigned long start,end,offset;\n  unsigned major_number,minor_number; unsigned long long inode; unsigned matches=0;\n  uintptr_t address=(uintptr_t)symbol;\n  while(fgets(line,sizeof(line),maps)) {\n    if(sscanf(line,"%lx-%lx %4s %lx %x:%x %llu",&start,&end,permissions,&offset,&major_number,&minor_number,&inode)!=7) continue;\n    if(address<start || address>=end) continue;\n    if(strcmp(permissions,"r-xp") || major_number!=major(file.st_dev) || minor_number!=minor(file.st_dev) ||\n       inode!=(unsigned long long)file.st_ino || (uint64_t)offset+address-start>=(uint64_t)file.st_size) exit(6);\n    ++matches;\n  }\n  fclose(maps); if(matches!=1) exit(6);\n}\nint main(int argc,char **argv) {\n  if(argc!=5) return 2;\n  uint64_t n=strtoull(argv[2],0,10), calls=strtoull(argv[3],0,10), seed=strtoull(argv[4],0,10);\n  if(n>65536 || calls==0 || calls>10000000 || seed>255) return 2;\n  void *lib=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL); if(!lib) { fprintf(stderr,"%s",dlerror()); return 4; }\n  uint64_t (*work)(size_t,uint32_t); *(void**)(&work)=dlsym(lib,"full_lifecycle"); if(!work) return 5;\n  mapped_image(argv[1],(void*)work);\n  uint64_t sum=0, start=ns(CLOCK_MONOTONIC), cpu=ns(CLOCK_PROCESS_CPUTIME_ID);\n  for(uint64_t i=0;i<calls;i++) sum+=work(n,(uint32_t)((seed+i)&255));\n  cpu=ns(CLOCK_PROCESS_CPUTIME_ID)-cpu; uint64_t elapsed=ns(CLOCK_MONOTONIC)-start;\n  printf("{\\"elapsed_ns\\":%" PRIu64 ",\\"process_cpu_ns\\":%" PRIu64 ",\\"checksum\\":%" PRIu64 ",\\"loaded_mapping_verified\\":true}\\n",elapsed,cpu,sum);\n  dlclose(lib); return 0;\n}\n'

def checksum(module, n, calls, seed):
    """Independent period-256 oracle for the declared bounded inputs only."""
    if module not in MODULES or not 0 <= n <= 65536 or not 0 < calls <= 1_000_000 or not 0 <= seed <= 255:
        raise ValueError("checksum outside the declared workload")
    values = []
    for offset in range(256):
        s = (seed + offset) & 255
        cycle = ([((i + s) & 255) for i in range(256)] if module == "byte_sum" else
                 [((13 * i + s) & 255) ^ ((i + (s ^ 90)) & 255) for i in range(256)])
        values.append((n // 256) * sum(cycle) + sum(cycle[:n % 256]))
    return ((calls // 256) * sum(values) + sum(values[:calls % 256])) & ((1 << 64) - 1)


def checksum_program(kind):
    if kind not in MODULES:
        raise ValueError("unknown Core fixture")
    raw = (Path(__file__).parent / "fixtures/hia_artifact_session" / (kind + ".core.hepta")).read_bytes()
    return verify_program(raw)
