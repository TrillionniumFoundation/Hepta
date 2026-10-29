#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
extern uint64_t entrypoint(uint32_t,uint32_t,uint32_t);
extern uint64_t provider_probe(uint32_t,uint32_t,uint32_t);
void *__real_malloc(size_t); void *__real_calloc(size_t,size_t); void __real_free(void*);
static int active=0; static uint64_t na,nf,live,peak,bad;
static void *ptrs[128]; static size_t sizes[128];
static void add(void*p,size_t n){if(!active||!p)return; for(int i=0;i<128;i++)if(!ptrs[i]){ptrs[i]=p;sizes[i]=n;na++;live+=n;if(live>peak)peak=live;return;}bad=1;}
void *__wrap_malloc(size_t n){void*p=__real_malloc(n);add(p,n);return p;}
void *__wrap_calloc(size_t a,size_t b){void*p=__real_calloc(a,b);add(p,a*b);return p;}
void __wrap_free(void*p){if(p)for(int i=0;i<128;i++)if(ptrs[i]==p){nf++;live-=sizes[i];ptrs[i]=0;break;}__real_free(p);}
static void reset(void){na=nf=peak=bad=0;if(live)bad=1;active=1;}
int main(void){uint32_t a,b,c;setbuf(stdout,0);while(scanf("%"SCNu32" %"SCNu32" %"SCNu32,&a,&b,&c)==3){
reset();uint64_t e=entrypoint(a,b,c);active=0;uint64_t ea=na,ef=nf,el=live,ep=peak,eb=bad;
reset();uint64_t p=provider_probe(a,b,c);active=0;
printf("%"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64"\n",e,p,ea,ef,el,ep,eb,na,nf,live,peak,bad);
}return 0;}
