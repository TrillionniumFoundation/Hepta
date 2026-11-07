
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
void *__real_calloc(size_t,size_t); void *__real_malloc(size_t); void __real_free(void*);
static unsigned long attempts, allocations, frees, live, refuse;
void *__wrap_calloc(size_t n,size_t m) {
    ++attempts; if(refuse && attempts==refuse)return NULL;
    void *p=__real_calloc(n,m); if(p){++allocations;++live;} return p;
}
void *__wrap_malloc(size_t n) {
    ++attempts; if(refuse && attempts==refuse)return NULL;
    void *p=__real_malloc(n); if(p){++allocations;++live;} return p;
}
void __wrap_free(void *p) {if(p){++frees;--live;} __real_free(p);}
extern unsigned long long ENTRY(size_t,unsigned long long,unsigned int,unsigned int);
int main(int argc,char **argv) {
    if(argc!=6)return 80;
    refuse=strtoul(argv[5],NULL,10);
    unsigned long long result=ENTRY(strtoul(argv[1],NULL,10),strtoull(argv[2],NULL,10),
        (unsigned int)strtoul(argv[3],NULL,10),(unsigned int)strtoul(argv[4],NULL,10));
    printf("{\"result\":%llu,\"attempts\":%lu,\"allocations\":%lu,\"frees\":%lu,\"live\":%lu}\n",
        result,attempts,allocations,frees,live);
    return live?81:0;
}
