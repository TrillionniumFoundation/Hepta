/* Actual-policy defensive controls for CT27..CT36.
 * Includes the current complete dispatcher solely to record real mechanical
 * calls. Every wrapper forwards the original operation once. No result or
 * terminal resource receipt is fabricated. This is a test binary only.
 */
#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

struct counts { uint64_t writes,closes,forks,kills,waits; };
static struct counts actual_counts,at_fault;
static ssize_t actual_write(int fd,const void *data,size_t count) {
    ++actual_counts.writes;return write(fd,data,count);
}
static int actual_close(int fd) {++actual_counts.closes;return close(fd);}
static pid_t actual_fork(void) {++actual_counts.forks;return fork();}
static int actual_kill(pid_t pid,int signum) {++actual_counts.kills;return kill(pid,signum);}
static pid_t actual_waitpid(pid_t pid,int *status,int options) {
    ++actual_counts.waits;return waitpid(pid,status,options);
}
#define write actual_write
#define close actual_close
#define fork actual_fork
#define kill actual_kill
#define waitpid actual_waitpid
#include "hia_cold_native_transport.c"
#undef write
#undef close
#undef fork
#undef kill
#undef waitpid

static hia_cold_policy actual_policy;
static const char *variant;
static unsigned hit,allocation_failed,first_zero,call_count,run_number;
static uint64_t rejected_sequence,memfd_number,memfd_seals,memfd_extent;
static uint64_t actual_competing_pid,actual_competing_status;
static unsigned char *policy_raw,*sealed_raw;
static size_t policy_size,policy_capacity,sealed_size;
static const unsigned char *target_bytes;
static size_t target_size;
#define CALL_BYTES 920

static int load_file(const char *name,unsigned char **out,size_t *size) {
    int fd=open(name,O_RDONLY|O_CLOEXEC);if(fd<0)return -1;
    struct stat st;if(fstat(fd,&st)||st.st_size<0||(uint64_t)st.st_size>SIZE_MAX){close(fd);return -1;}
    size_t n=(size_t)st.st_size;
    unsigned char *raw=malloc(n?n:1);if(!raw){close(fd);return -1;}
    size_t at=0;
    while(at<n){ssize_t k=read(fd,raw+at,n-at);if(k<0&&errno==EINTR)continue;
        if(k<=0){free(raw);close(fd);return -1;}at+=(size_t)k;}
    if(close(fd)){free(raw);return -1;}*out=raw;*size=n;return 0;
}
static int save_file(const char *directory,const char *name,const void *raw,size_t size) {
    char path[4096];int n=snprintf(path,sizeof path,"%s/%s",directory,name);
    if(n<0||(size_t)n>=sizeof path)return -1;
    int fd=open(path,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);if(fd<0)return -1;
    size_t at=0;while(at<size){ssize_t k=write(fd,(const unsigned char*)raw+at,size-at);
        if(k<0&&errno==EINTR)continue;if(k<=0){close(fd);return -1;}at+=(size_t)k;}
    return close(fd);
}
static int append_policy(const unsigned char *raw) {
    if(policy_size>SIZE_MAX-CALL_BYTES)return -1;
    size_t needed=policy_size+CALL_BYTES;
    if(needed>policy_capacity) {
        size_t capacity=policy_capacity?policy_capacity*2:CALL_BYTES*16;
        if(capacity<needed)capacity=needed;
        void *next=realloc(policy_raw,capacity);if(!next)return -1;
        policy_raw=next;policy_capacity=capacity;
    }
    memcpy(policy_raw+policy_size,raw,CALL_BYTES);policy_size=needed;return 0;
}
static void reseal(unsigned char *reply) {
    uint64_t value=HCT_CANARY;
    for(unsigned i=0;i<7;++i)value^=get64(reply+8*i);
    put64(reply+56,value);
}
static int is(const char *name){return strcmp(variant,name)==0;}
static int takes_fault(uint64_t action,const unsigned char *request) {
    if(hit)return 0;
    if(is("short-live"))return action==HCT_CLOCK;
    if(is("action")||is("amount")||is("oob-image"))return action==HCT_IMAGE_WRITE;
    if(is("argument")||is("bad-slot"))return action==HCT_PIPE;
    if(is("auxiliary")||is("oob-stdin"))return action==HCT_STDIN_WRITE;
    if(is("duplicate-close"))return get64(request+24)==HCT_CLOSE;
    if(is("second-fork"))return get64(request+104)>0;
    if(is("owner-lost"))return action==HCT_WAIT_NOHANG||action==HCT_WAIT_BLOCK;
    return action==HCT_MEMFD;
}
static uint64_t observing_policy(const void *source,uint64_t size,void *output,
        uint64_t capacity,void *workspace,uint64_t space) {
    if(size!=128||capacity!=64||space!=256){allocation_failed=1;return 0;}
    unsigned char record[CALL_BYTES]={0};
    unsigned char *request=(unsigned char*)source,*reply=output,*state=workspace;
    if(call_count==0){first_zero=1;for(unsigned i=0;i<256;++i)if(state[i])first_zero=0;}
    ++call_count;
    put64(record,call_count);put64(record+8,run_number);
    memcpy(record+24,request,128);memcpy(record+408,state,256);
    if(get64(request+24)==HCT_MEMFD&&get64(request+40)==0)memfd_number=get64(request+48);
    if(get64(request+24)==HCT_SEAL_GET&&get64(request+40)==0&&memfd_number) {
        struct stat info;
        int fd=(int)memfd_number;
        int flags=fcntl(fd,F_GET_SEALS);
        if(flags<0||fstat(fd,&info)||info.st_size<0){allocation_failed=1;return 0;}
        memfd_seals=(uint64_t)flags;memfd_extent=(uint64_t)info.st_size;
        if(is("seals")&&!sealed_raw) {
            sealed_size=(size_t)info.st_size;sealed_raw=malloc(sealed_size?sealed_size:1);
            if(!sealed_raw){allocation_failed=1;return 0;}
            size_t at=0;
            while(at<sealed_size){ssize_t n=pread(fd,sealed_raw+at,sealed_size-at,(off_t)at);
                if(n<0&&errno==EINTR)continue;if(n<=0){allocation_failed=1;return 0;}at+=(size_t)n;}
        }
    }
    uint64_t returned=actual_policy(source,size,output,capacity,workspace,space);
    memcpy(record+280,reply,64);
    uint64_t action=get64(reply+24);
    int has_fault=!(is("seals")||is("fresh")||is("overflow")
        ||is("closed-0")||is("closed-1")||is("closed-2")
        ||is("sigpipe-default")||is("sigchld-ignore")||is("sigchld-no-cldwait"));
    if(returned==64&&has_fault&&takes_fault(action,request)) {
        hit=1;at_fault=actual_counts;rejected_sequence=get64(reply+16);
        if(is("short-initial")||is("short-live"))returned=63;
        else if(is("nonce"))put64(reply+8,get64(reply+8)^1);
        else if(is("sequence"))put64(reply+16,get64(reply+16)+1);
        else if(is("repeat-sequence"))put64(reply+16,get64(request+16));
        else if(is("action")){put64(reply+24,HCT_CLOSE);put64(reply+32,0);}
        else if(is("argument"))put64(reply+32,get64(reply+32)+1);
        else if(is("amount"))put64(reply+40,get64(reply+40)+1);
        else if(is("auxiliary"))put64(reply+48,get64(reply+48)+1);
        else if(is("ack-action"))put64(request+24,get64(request+24)^1);
        else if(is("ack-argument"))put64(request+32,get64(request+32)^1);
        else if(is("workspace-magic"))put64(state,get64(state)^1);
        else if(is("workspace-issued-action"))put64(state+24,get64(state+24)^1);
        else if(is("request-byte"))request[72]^=1;
        else if(is("request-canary"))request[120]^=1;
        else if(is("reply-checksum"))reply[56]^=1;
        else if(is("workspace-canary")) {
            struct guarded_state *guard=(struct guarded_state*)((unsigned char*)workspace-
                offsetof(struct guarded_state,bytes));
            guard->after^=1;
        }
        else if(is("bad-slot")){put64(reply+24,HCT_CLOSE);put64(reply+32,9);}
        else if(is("duplicate-close")){put64(reply+24,HCT_CLOSE);put64(reply+32,get64(request+32));}
        else if(is("second-fork")){put64(reply+24,HCT_FORK_EXEC);put64(reply+32,0);}
        else if(is("oob-image"))put64(reply+40,target_size);
        else if(is("oob-stdin"))put64(reply+40,get64(request+80));
        else if(is("owner-lost")) {
            int status=0;pid_t pid=(pid_t)get64(request+104),got;
            do{got=waitpid(pid,&status,0);}while(got<0&&errno==EINTR);
            if(got!=pid){allocation_failed=1;return 0;}
            actual_competing_pid=(uint64_t)got;actual_competing_status=(uint64_t)(unsigned)status;
        } else {allocation_failed=1;return 0;}
        if(!is("reply-checksum"))reseal(reply);
    }
    put64(record+16,returned);
    memcpy(record+152,request,128);memcpy(record+344,reply,64);memcpy(record+664,state,256);
    if(append_policy(record)){allocation_failed=1;return 0;}
    return returned;
}
static int allowed_variant(const char *value) {
    static const char *names[]={
        "short-initial","short-live","nonce","sequence","repeat-sequence",
        "action","argument","amount","auxiliary","ack-action","ack-argument",
        "workspace-magic","workspace-issued-action","request-byte","request-canary",
        "reply-checksum","workspace-canary","bad-slot","duplicate-close","second-fork",
        "oob-image","oob-stdin","seals","fresh","overflow",
        "closed-0","closed-1","closed-2","sigpipe-default","sigchld-ignore",
        "sigchld-no-cldwait","owner-lost"
    };
    for(size_t i=0;i<sizeof names/sizeof names[0];++i)if(strcmp(value,names[i])==0)return 1;
    return 0;
}
static int entry_refusal(void) {
    return is("closed-0")||is("closed-1")||is("closed-2")
        ||is("sigpipe-default")||is("sigchld-ignore")||is("sigchld-no-cldwait");
}
static void print_counts(FILE *out,struct counts c) {
    fprintf(out,"{\"write\":%" PRIu64 ",\"close\":%" PRIu64 ",\"fork\":%" PRIu64
        ",\"kill\":%" PRIu64 ",\"wait\":%" PRIu64 "}",c.writes,c.closes,c.forks,c.kills,c.waits);
}
int main(int argc,char **argv) {
    if(argc!=5||!allowed_variant(argv[3]))return 64;
    variant=argv[3];
    unsigned char *policy=NULL,*target=NULL;size_t policy_bytes=0;
    if(load_file(argv[1],&policy,&policy_bytes)||load_file(argv[2],&target,&target_size)
        ||!policy_bytes||!target_size)return 65;
    target_bytes=target;
    if(save_file(argv[4],"consumed-policy.bin",policy,policy_bytes)
        ||save_file(argv[4],"consumed-target.bin",target,target_size))return 65;
    void *mapping=mmap(NULL,policy_bytes,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(mapping==MAP_FAILED)return 66;
    memcpy(mapping,policy,policy_bytes);free(policy);
    if(mprotect(mapping,policy_bytes,PROT_READ|PROT_EXEC))return 66;
    _Static_assert(sizeof actual_policy==sizeof mapping,"SysV pointer");
    memcpy(&actual_policy,&mapping,sizeof actual_policy);
    struct sigaction original_pipe,original_child,selected_pipe,selected_child;
    if(sigaction(SIGPIPE,NULL,&original_pipe)||sigaction(SIGCHLD,NULL,&original_child))return 67;
    memset(&selected_pipe,0,sizeof selected_pipe);sigemptyset(&selected_pipe.sa_mask);
    selected_pipe.sa_handler=SIG_IGN;
    memset(&selected_child,0,sizeof selected_child);sigemptyset(&selected_child.sa_mask);
    selected_child.sa_handler=SIG_DFL;
    if(is("sigpipe-default"))selected_pipe.sa_handler=SIG_DFL;
    if(is("sigchld-ignore"))selected_child.sa_handler=SIG_IGN;
    if(is("sigchld-no-cldwait"))selected_child.sa_flags=SA_NOCLDWAIT;
    if(sigaction(SIGPIPE,&selected_pipe,NULL)||sigaction(SIGCHLD,&selected_child,NULL))return 67;
    unsigned char input[131077];for(size_t i=0;i<sizeof input;++i)input[i]=(unsigned char)i;
    unsigned runs=is("fresh")?2:1,complete=1;
    char path[4096];int n=snprintf(path,sizeof path,"%s/report.json",argv[4]);
    if(n<0||(size_t)n>=sizeof path)return 68;
    FILE *report=fopen(path,"wx");if(!report)return 68;
    fprintf(report,"{\"schema\":\"hepta.cold-native-transport.ct36-policy.v4\",\"variant\":\"%s\",\"runs\":[",variant);
    for(run_number=0;run_number<runs;++run_number) {
        char directory[4096];n=snprintf(directory,sizeof directory,"%s/run-%u",argv[4],run_number);
        if(n<0||(size_t)n>=sizeof directory||mkdir(directory,0700))return 68;
        const char *mode=is("seals")?"extent":is("short-live")?"pause":is("overflow")?"stdout":
            (is("auxiliary")||is("oob-stdin"))?"echo":"identity";
        const char *arguments[]={"--ct36",mode};
        struct hia_cold_config config={target,target_size,input,sizeof input,directory,
            arguments,2,NULL,0,UINT64_C(20000000000),
            UINT64_C(1128353841000)+run_number,0,NULL,NULL};
        if(strcmp(mode,"echo")!=0){config.input=NULL;config.input_bytes=0;}
        size_t trace_capacity=is("overflow")?1:8192;
        struct hia_cold_event *trace=calloc(trace_capacity,sizeof *trace);if(!trace)return 69;
        int missing=entry_refusal()&&strncmp(variant,"closed-",7)==0?variant[7]-'0':-1;
        int backup=-1;
        if(missing>=0){backup=fcntl(missing,F_DUPFD_CLOEXEC,3);if(backup<0||close(missing))return 70;}
        actual_counts=(struct counts){0};at_fault=(struct counts){0};
        hit=allocation_failed=first_zero=call_count=0;
        rejected_sequence=memfd_number=memfd_seals=memfd_extent=0;
        actual_competing_pid=actual_competing_status=0;
        size_t policy_begin=policy_size;
        struct hia_cold_result result;
        int rc=hia_cold_transport_run(observing_policy,&config,&result,trace,trace_capacity);
        int call_errno=errno;
        struct sigaction after_pipe,after_child;
        if(sigaction(SIGPIPE,NULL,&after_pipe)||sigaction(SIGCHLD,NULL,&after_child))return 70;
        int dispositions_unchanged=after_pipe.sa_handler==selected_pipe.sa_handler
            &&after_child.sa_handler==selected_child.sa_handler
            &&((after_child.sa_flags^selected_child.sa_flags)&SA_NOCLDWAIT)==0;
        if(missing>=0){if(dup2(backup,missing)!=missing||close(backup))return 70;}
        int memfd_closed=0;
        if(memfd_number){errno=0;int flags=fcntl((int)memfd_number,F_GETFD);memfd_closed=flags<0&&errno==EBADF;}
        int passed=allocation_failed==0&&dispositions_unchanged&&result.final_fd_mask==0
            &&(!memfd_number||memfd_closed);
        int gone=0;
        if(result.child_pid>0){errno=0;int k=kill((pid_t)result.child_pid,0);gone=k<0&&errno==ESRCH;}
        if(entry_refusal())passed=passed&&call_count==0&&rc==-1&&result.outcome==HCT_SYSTEM_ERROR
            &&result.primary_errno==EINVAL&&result.spawned==0&&actual_counts.forks==0;
        else if(is("owner-lost"))passed=passed&&hit==1&&actual_competing_pid==(uint64_t)result.child_pid
            &&result.owner_lost==1&&result.reaped==0&&result.outcome==HCT_CUSTODY_LOST
            &&rc==-1&&actual_counts.kills==0&&gone;
        else if(is("seals")||is("fresh")||is("overflow")) {
            passed=passed&&rc==0&&result.policy_complete==1&&result.outcome==HCT_RETURNED
                &&result.reaped==1&&result.returncode==0&&actual_counts.forks==1&&first_zero&&gone;
            if(is("seals"))passed=passed&&sealed_size==target_size&&memfd_extent==target_size
                &&memfd_seals==15&&memcmp(sealed_raw,target,target_size)==0;
            if(is("overflow"))passed=passed&&result.trace_overflow==1&&result.stdout_size==98347;
            else passed=passed&&result.trace_overflow==0;
        } else passed=passed&&hit==1&&rc==-1&&result.policy_complete==0&&result.outcome==HCT_POLICY_LOST
            &&result.action_count+1==rejected_sequence&&result.trace_overflow==0
            &&(!result.spawned||(result.reaped==1&&gone));
        if(!passed)complete=0;
        size_t trace_count=result.action_count<trace_capacity?(size_t)result.action_count:trace_capacity;
        if(save_file(directory,"stdout.bin",result.stdout_bytes,result.stdout_size)
          ||save_file(directory,"stderr.bin",result.stderr_bytes,result.stderr_size)
          ||save_file(directory,"events.bin",trace,trace_count*sizeof *trace)
          ||save_file(directory,"policy-calls.bin",policy_raw?policy_raw+policy_begin:NULL,policy_size-policy_begin))return 71;
        if(is("seals")&&save_file(directory,"sealed-image.bin",sealed_raw,sealed_size))return 71;
        fprintf(report,"%s{\"run\":%u,\"passed\":%s,\"rc\":%d,\"errno_after_call\":%d,"
            "\"nonce\":%" PRIu64 ",\"calls\":%u,\"first_workspace_zero\":%s,"
            "\"fault_hits\":%u,\"rejected_sequence\":%" PRIu64 ",\"outcome\":%u,"
            "\"primary_errno\":%u,\"primary_stage\":%u,\"cleanup_errno\":%u,\"cleanup_stage\":%u,"
            "\"pid\":%" PRId64 ",\"returncode\":%d,\"wait_status\":%d,\"spawned\":%u,"
            "\"exec_confirmed\":%u,\"reaped\":%u,\"owner_lost\":%u,\"policy_complete\":%u,"
            "\"trace_overflow\":%u,\"entries\":%" PRIu64 ",\"trace_count\":%zu,"
            "\"trace_item_bytes\":%zu,\"policy_item_bytes\":%d,\"final_fd_mask\":%" PRIu64 ","
            "\"stdout_size\":%zu,\"stderr_size\":%zu,\"stdout_reads\":%zu,\"stderr_reads\":%zu,"
            "\"start_ns\":%" PRIu64 ",\"end_ns\":%" PRIu64 ",\"actual_child_gone\":%s,"
            "\"dispositions_unchanged\":%s,\"memfd\":%" PRIu64 ",\"seals\":%" PRIu64 ","
            "\"extent\":%" PRIu64 ",\"competing_wait_pid\":%" PRIu64 ","
            "\"competing_wait_status\":%" PRIu64 ",\"effects_before_fault\":",
            run_number?",":"",run_number,passed?"true":"false",rc,call_errno,
            result.nonce,call_count,first_zero?"true":"false",hit,rejected_sequence,
            result.outcome,result.primary_errno,result.primary_stage,result.cleanup_errno,
            result.cleanup_stage,result.child_pid,result.returncode,result.wait_status,result.spawned,
            result.exec_confirmed,result.reaped,result.owner_lost,result.policy_complete,
            result.trace_overflow,result.action_count,trace_count,sizeof *trace,CALL_BYTES,result.final_fd_mask,
            result.stdout_size,result.stderr_size,result.stdout_reads,result.stderr_reads,
            result.start_ns,result.end_ns,gone?"true":"false",dispositions_unchanged?"true":"false",
            memfd_number,memfd_seals,memfd_extent,actual_competing_pid,actual_competing_status);
        print_counts(report,at_fault);fprintf(report,",\"actual_effects\":");print_counts(report,actual_counts);
        fprintf(report,",\"actual_memfd_closed\":%s}",memfd_closed?"true":"false");
        hia_cold_transport_release(&result);free(trace);
    }
    fprintf(report,"],\"status\":\"%s\",\"whole_native\":false,\"qualification_complete\":false}\n",
        complete?"CONTROLS_OBSERVED":"HOLD");
    if(fclose(report))complete=0;
    if(sigaction(SIGPIPE,&original_pipe,NULL)||sigaction(SIGCHLD,&original_child,NULL))complete=0;
    free(policy_raw);free(sealed_raw);free(target);
    if(munmap(mapping,policy_bytes))complete=0;
    return complete?0:1;
}
