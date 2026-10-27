#include "bridge.h"
#include "hepta.h"
#include "selected.hpp"
#include "cases.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>
#include <sys/resource.h>

namespace {
std::uint64_t allocations=0, releases=0, attempts=0, reject_at=0;
constexpr std::int64_t sentinel=9223372036854775807LL;
void require(bool condition, const char* message) {
    if (!condition) { std::fprintf(stderr,"%s\n",message); std::exit(2); }
}
std::uint64_t live() { return allocations-releases; }
}
void* operator new(std::size_t size) {
    ++attempts;
    if (reject_at && attempts==reject_at) throw std::bad_alloc();
    if (auto* memory=std::malloc(size?size:1)) { ++allocations; return memory; }
    throw std::bad_alloc();
}
void operator delete(void* memory) noexcept {if (memory) {++releases; std::free(memory);} }
void operator delete(void* memory,std::size_t) noexcept {::operator delete(memory);}
void* operator new[](std::size_t size) {return ::operator new(size);}
void operator delete[](void* memory) noexcept {::operator delete(memory);}
void operator delete[](void* memory,std::size_t) noexcept {::operator delete(memory);}

int vector_operation(bool hepta,const VectorCase& c,std::int64_t* out) {
    if (hepta) return hepta_vector_deque(c.count,c.initial,c.appended,c.index,c.other_count,c.other_index,out);
    try {
        auto result=[&]() -> std::int64_t {
            std::vector<std::int64_t> first(c.count,c.initial);
            first.push_back(c.appended);
            const std::int64_t copied=first.at(c.index);
            std::deque<std::int64_t> second(c.other_count,copied);
            return second.at(c.other_index);
        }();
        *out=result; return 0;
    } catch (...) { return 3; }
}

int json_operation(bool hepta,const JsonCase& c,std::int64_t* out) {
    auto* first=reinterpret_cast<const std::uint8_t*>(c.first);
    auto* second=reinterpret_cast<const std::uint8_t*>(c.second);
    if (hepta) return hepta_json_chain(first,std::strlen(c.first),second,std::strlen(c.second),
                                     c.index,c.replacement,c.count,c.final_index,out);
    try {
        auto result=[&]() -> std::int64_t {
            hepta_json_upgrade::Document left(std::span<const std::uint8_t>(first,std::strlen(c.first)));
            left.replace(c.index,c.replacement);
            const std::int64_t left_sum=left.sum();
            hepta_json_upgrade::Document right(std::span<const std::uint8_t>(second,std::strlen(c.second)));
            right.replace(c.index,left_sum);
            const std::int64_t right_sum=right.sum();
            std::vector<std::int64_t> values(c.count,right_sum);
            return values.at(c.final_index);
        }();
        *out=result; return 0;
    } catch (...) { return 3; }
}

int calibrated_operation(unsigned kind,bool hepta,std::int64_t* out) {
    if (!kind) return vector_operation(hepta,VectorCase{2,7,11,2,3,1},out);
    return json_operation(hepta,JsonCase{"{\"values\":[1,2,3]}","{\"values\":[2,4,6]}",1,5,3,1},out);
}

int main(int argc,char** argv) {
    struct rlimit no_core {0,0};
    require(setrlimit(RLIMIT_CORE,&no_core)==0,"disable fault-injection core dumps");
    if (argc==4 || argc==5) {
        require(std::strcmp(argv[1],"--calibrate")==0 || std::strcmp(argv[1],"--fault")==0,"mode");
        auto kind=static_cast<unsigned>(std::strtoul(argv[2],nullptr,10));
        auto route=static_cast<unsigned>(std::strtoul(argv[3],nullptr,10));
        require(kind<2 && route<2,"route");
        const std::int64_t expected=kind?17:11;
        const auto before=live(),start=attempts;
        std::int64_t out=sentinel;
        require(calibrated_operation(kind,route,&out)==0 && out==expected && live()==before,"calibration result/leak");
        const auto sites=attempts-start;
        require(sites>0 && sites<256,"allocation denominator");
        if (argc==4) {
            require(std::strcmp(argv[1],"--calibrate")==0,"calibration argv");
            std::printf("{\"kind\":%u,\"route\":%u,\"sites\":%llu,\"value\":%lld,\"live_delta\":0}\n",
                        kind,route,static_cast<unsigned long long>(sites),static_cast<long long>(out));
            return 0;
        }
        require(std::strcmp(argv[1],"--fault")==0,"fault argv");
        const auto site=std::strtoull(argv[4],nullptr,10);
        require(site>0 && site<=sites,"fault site");
        out=sentinel; reject_at=attempts+site;
        auto status=calibrated_operation(kind,route,&out);
        reject_at=0;
        require(status==3 && out==sentinel && live()==before,"caught failure cleanup/output");
        require(calibrated_operation(kind,route,&out)==0 && out==expected && live()==before,"recovery");
        std::printf("{\"site\":%llu,\"status\":3,\"live_delta\":0,\"output_preserved\":true,\"recovered\":true}\n",
                    static_cast<unsigned long long>(site));
        return 0;
    }
    require(argc==1,"unexpected arguments");
    std::printf("{\"version\":\"%d.%d.%d\",\"vector_cases\":[",NLOHMANN_JSON_VERSION_MAJOR,
                NLOHMANN_JSON_VERSION_MINOR,NLOHMANN_JSON_VERSION_PATCH);
    for (std::size_t i=0;i<sizeof(vector_cases)/sizeof(vector_cases[0]);++i) {
        const auto before=live(); std::int64_t direct=sentinel,hepta=sentinel;
        int a=vector_operation(false,vector_cases[i],&direct);
        require(live()==before,"direct STL lifetime leaked");
        int b=vector_operation(true,vector_cases[i],&hepta);
        require(live()==before,"composed STL bridge leaked");
        std::printf("%s{\"id\":%zu,\"direct_status\":%d,\"direct_value\":%lld,\"hepta_status\":%d,\"hepta_value\":%lld,\"live_delta\":0}",
                    i?",":"",i,a,static_cast<long long>(direct),b,static_cast<long long>(hepta));
    }
    std::printf("],\"json_cases\":[");
    for (std::size_t i=0;i<sizeof(json_cases)/sizeof(json_cases[0]);++i) {
        const auto before=live(); std::int64_t direct=sentinel,hepta=sentinel;
        int a=json_operation(false,json_cases[i],&direct);
        require(live()==before,"direct JSON lifetime leaked");
        int b=json_operation(true,json_cases[i],&hepta);
        require(live()==before,"composed JSON bridge leaked");
        std::printf("%s{\"id\":%zu,\"direct_status\":%d,\"direct_value\":%lld,\"hepta_status\":%d,\"hepta_value\":%lld,\"live_delta\":0}",
                    i?",":"",i,a,static_cast<long long>(direct),b,static_cast<long long>(hepta));
    }
    std::int64_t out=sentinel;
    require(hepta_json_chain(nullptr,1,nullptr,0,0,0,0,0,&out)==1 && out==sentinel,"null input");
    require(hepta_vector_deque(1,1,2,0,1,0,nullptr)==1,"null output");
    std::printf("],\"pointer_guards\":2,\"ordinary_live_delta\":0}\n");
}
