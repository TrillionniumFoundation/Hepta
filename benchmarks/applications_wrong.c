#include "applications.h"
/* Deliberately linked as an actual executable for the oracle rejection gate. */
AppResult packet_app(size_t units,uint64_t request){
    (void)request;AppResult result={0,0,units*64,units,0};return result;
}
AppResult transform_app(size_t units,uint64_t request){
    (void)request;AppResult result={0,0,units*256,units,0};return result;
}
