
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
size_t opaque_loop(size_t,uint32_t);
uint8_t read_nonentry(size_t);
uint8_t read_returned(size_t);
void *__real_malloc(size_t);
void __real_free(void*);
static void *live[64];
static unsigned attempts, nm, nc, nf, active, bad;
static void remember(void *p){if(!p)return;for(int i=0;i<64;i++)if(!live[i]){live[i]=p;active++;return;}bad=1;}
void *__wrap_malloc(size_t n){attempts++;nm++;if(n==13)return 0;void*p=__real_malloc(n);if(p)memset(p,0xA7,n);remember(p);return p;}
void *__wrap_calloc(size_t n,size_t s){attempts++;nc++;void*p=__real_malloc(n*s);if(p)memset(p,0,n*s);remember(p);return p;}
void __wrap_free(void *p){if(!p)return;for(int i=0;i<64;i++)if(live[i]==p){live[i]=0;active--;nf++;__real_free(p);return;}bad=1;}
int main(void){
 if(opaque_loop(0,7)!=0 || opaque_loop(1,7)!=1 || opaque_loop(13,2)!=999 || opaque_loop(((size_t)1)<<63,2)!=999 || opaque_loop(17,4)!=17)return 2;
 if(read_nonentry(1)!=0 || read_returned(1)!=0)return 3;
 printf("attempts=%u malloc=%u calloc=%u frees=%u live=%u bad=%u\n",attempts,nm,nc,nf,active,bad);
 return attempts!=5 || nm!=3 || nc!=2 || nf!=4 || active!=0 || bad!=0;
}
