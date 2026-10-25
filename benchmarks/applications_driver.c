#define _POSIX_C_SOURCE 200809L
#include "applications.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>

/* Independent native oracle. Its allocation, generation and checking occur
 * outside each measured request. Smaller fixed cases are also checked against
 * a separately written Python oracle by the qualification tool. */
static uint64_t random_next(uint64_t *state){
    *state=*state*UINT64_C(6364136223846793005)+UINT64_C(1442695040888963407);return *state;
}
static uint64_t hash_byte(uint64_t hash,unsigned byte){return(hash^(uint8_t)byte)*UINT64_C(1099511628211);}
static AppResult empty(uint32_t status){AppResult r={status,0,0,0,0};return r;}
static int valid_units(size_t units){return units>0 && units<=4096;}
static int phase_count(int application,size_t units,uint64_t request){
    if(!valid_units(units))return 0;
    return application==0?2:(request%8==1?1:3);
}
static AppResult reference(int application,size_t units,uint64_t request,size_t fail_nth){
    if(!valid_units(units))return empty(1);
    if(fail_nth && fail_nth<=(size_t)phase_count(application,units,request))return empty(10);
    if(application==0){
        size_t length=units*64;
        uint8_t *wire=malloc(length);if(!wire)exit(72);
        uint64_t state=request^UINT64_C(11400714819323198485);
        for(size_t frame=0;frame<units;frame++){
            uint8_t *start=wire+frame*64;
            start[0]=60;start[1]=0;start[2]=(uint8_t)(random_next(&state)&7);
            unsigned sum=0;
            for(size_t i=0;i<60;i++){start[4+i]=(uint8_t)(random_next(&state)>>32);sum+=start[4+i];}
            start[3]=(uint8_t)sum;
        }
        size_t middle=(units/2)*64;
        switch(request%8){case 1:wire[middle]=61;break;case 2:wire[middle+4]^=1;break;case 3:wire[middle+2]=8;break;default:break;}
        uint8_t counts[256]={0};
        AppResult r={0,0,0,0,UINT64_C(14695981039346656037)};
        while(r.bytes<length){
            const uint8_t *frame=wire+r.bytes;
            size_t available=length-(size_t)r.bytes;
            if(available<4){r.status=2;break;}
            size_t payload=(size_t)frame[0]+(size_t)frame[1]*256;
            if(payload!=60 || payload>available-4){r.status=2;break;}
            if(frame[2]>7){r.status=4;break;}
            unsigned sum=0;
            for(size_t i=4;i<4+payload;i++){sum+=frame[i];r.checksum=hash_byte(r.checksum,frame[i]);}
            if((uint8_t)sum!=frame[3]){r.status=3;break;}
            counts[frame[2]]++;r.bytes+=payload+4;r.records++;
        }
        if(!r.status)for(size_t i=0;i<256;i++)r.checksum=hash_byte(r.checksum,counts[i]);
        free(wire);return r;
    }
    if(request%8==1)return empty(2);
    size_t length=units*256;
    uint8_t *output=malloc(length);if(!output)exit(72);
    uint64_t state=request^UINT64_C(15111065706836454659);
    uint8_t previous=(uint8_t)request;
    /* The oracle streams input directly into the reverse-position output; it
     * does not share the application's input/scratch/output implementation. */
    for(size_t index=0;index<length;index++){
        uint8_t byte=(uint8_t)(random_next(&state)>>32);
        uint8_t rotated=(uint8_t)(((unsigned)byte<<3)|(byte>>5));
        previous=rotated^previous;
        size_t target=(index/256)*256+255-index%256;
        output[target]=previous^(uint8_t)target;
    }
    AppResult r={0,0,length,units,UINT64_C(14695981039346656037)};
    for(size_t index=0;index<length;index++)r.checksum=hash_byte(r.checksum,output[index]);
    free(output);return r;
}
static int equal_result(AppResult a,AppResult b){
    return a.status==b.status && a.reserved==b.reserved && a.bytes==b.bytes && a.records==b.records && a.checksum==b.checksum;
}
static int allocation_matches(int application,size_t units,uint64_t request,size_t fail_nth,AppAllocationMetrics m){
    size_t phases=(size_t)phase_count(application,units,request);
    size_t sizes[3]={application==0?units*64:units*256+4,256,units*256};
    size_t attempts=fail_nth && fail_nth<=phases?fail_nth:phases;
    size_t failures=fail_nth && fail_nth<=phases?1:0;
    size_t successes=attempts-failures;
    uint64_t attempted_bytes=0,allocated_bytes=0;
    for(size_t i=0;i<attempts;i++)attempted_bytes+=sizes[i];
    for(size_t i=0;i<successes;i++)allocated_bytes+=sizes[i];
    return m.attempts==attempts && m.allocations==successes && m.frees==successes && m.failures==failures
        && m.malloc_calls+m.calloc_calls+m.realloc_calls==attempts && m.realloc_calls==0
        && m.attempted_bytes==attempted_bytes && m.allocated_bytes==allocated_bytes
        && m.freed_bytes==allocated_bytes && m.peak_live_bytes==allocated_bytes && m.live_bytes==0;
}
static uint64_t nanoseconds(void){
    struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t)!=0)exit(73);
    return(uint64_t)t.tv_sec*UINT64_C(1000000000)+(uint64_t)t.tv_nsec;
}
static uint64_t result_digest(uint64_t h,AppResult r){
    h=hash_byte(h,r.status);h^=r.bytes;h*=UINT64_C(1099511628211);
    h^=r.records;h*=UINT64_C(1099511628211);return h^r.checksum;
}
static long address_space_high_water(void){
    FILE *stream=fopen("/proc/self/status","r");if(!stream)return -1;
    char line[256];long result=-1;
    while(fgets(line,sizeof(line),stream))if(sscanf(line,"VmHWM: %ld kB",&result)==1)break;
    fclose(stream);return result;
}
int main(int argc,char **argv){
    if(argc!=7){fprintf(stderr,"application units first_request count fail_nth warmups required\n");return 64;}
    int app=strcmp(argv[1],"packet")==0?0:strcmp(argv[1],"transform")==0?1:-1;
    size_t units=(size_t)strtoull(argv[2],NULL,10);
    uint64_t first=strtoull(argv[3],NULL,10);
    size_t count=(size_t)strtoull(argv[4],NULL,10),fail_nth=(size_t)strtoull(argv[5],NULL,10),warmups=(size_t)strtoull(argv[6],NULL,10);
    if(app<0 || count<1 || count>4096 || units>8192 || fail_nth>3 || warmups>64 || first>UINT64_MAX-65536)return 64;
    AppResult(*call)(size_t,uint64_t)=app==0?packet_app:transform_app;
    struct rusage before,after;if(getrusage(RUSAGE_SELF,&before)!=0)return 74;
    long vm_hwm_before=address_space_high_water();
    uint64_t warmup_hash=UINT64_C(14695981039346656037);
    for(size_t i=0;i<warmups;i++){
        uint64_t request=first+i;AppResult r=call(units,request),expected=reference(app,units,request,0);
        if(!equal_result(r,expected)){fprintf(stderr,"warmup oracle rejected result\n");return 40;}
        warmup_hash=result_digest(warmup_hash,r);
    }
    uint64_t calibration_min=UINT64_MAX;
    for(size_t i=0;i<128;i++){uint64_t start=nanoseconds(),elapsed=nanoseconds()-start;if(elapsed<calibration_min)calibration_min=elapsed;}
    for(size_t i=0;i<count;i++){
        uint64_t request=first+i*(fail_nth?8:1);size_t fault=i==0?fail_nth:0;
        app_measure_begin(fault);
        uint64_t start=nanoseconds();AppResult r=call(units,request);uint64_t elapsed=nanoseconds()-start;
        AppAllocationMetrics allocation=app_measure_end();
        AppResult expected=reference(app,units,request,fault);
        if(!equal_result(r,expected)){fprintf(stderr,"request oracle rejected result: %zu\n",i);return 41;}
        if(!allocation_matches(app,units,request,fault,allocation)){fprintf(stderr,"request oracle rejected allocation protocol: %zu\n",i);return 42;}
        if(!elapsed)return 43;
        printf("{\"request_id\":%"PRIu64",\"fault_nth\":%zu,\"elapsed_ns\":%"PRIu64",\"oracle_checked\":true,"
               "\"result\":{\"status\":%u,\"reserved\":%u,\"bytes\":%"PRIu64",\"records\":%"PRIu64",\"checksum\":%"PRIu64"},"
               "\"allocation\":{\"attempts\":%"PRIu64",\"allocations\":%"PRIu64",\"frees\":%"PRIu64",\"failures\":%"PRIu64","
               "\"malloc_calls\":%"PRIu64",\"calloc_calls\":%"PRIu64",\"realloc_calls\":%"PRIu64","
               "\"attempted_bytes\":%"PRIu64",\"allocated_bytes\":%"PRIu64",\"freed_bytes\":%"PRIu64",\"peak_live_bytes\":%"PRIu64",\"live_bytes\":%"PRIu64"}}\n",
               request,fault,elapsed,r.status,r.reserved,r.bytes,r.records,r.checksum,
               allocation.attempts,allocation.allocations,allocation.frees,allocation.failures,
               allocation.malloc_calls,allocation.calloc_calls,allocation.realloc_calls,
               allocation.attempted_bytes,allocation.allocated_bytes,allocation.freed_bytes,allocation.peak_live_bytes,allocation.live_bytes);
    }
    if(getrusage(RUSAGE_SELF,&after)!=0)return 74;
    printf("{\"summary\":true,\"requests\":%zu,\"warmups\":%zu,\"warmup_checksum\":%"PRIu64","
           "\"timer_pair_min_ns\":%"PRIu64",\"rss_start_kib\":%ld,\"rss_peak_kib\":%ld,"
           "\"rss_vm_hwm_start_kib\":%ld,\"rss_vm_hwm_peak_kib\":%ld,\"abi_size\":%zu}\n",
           count,warmups,warmup_hash,calibration_min,before.ru_maxrss,after.ru_maxrss,
           vm_hwm_before,address_space_high_water(),sizeof(AppResult));
    return 0;
}
