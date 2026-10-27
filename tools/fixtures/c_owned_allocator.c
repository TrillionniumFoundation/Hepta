
void *__real_calloc(size_t, size_t);
void __real_free(void *);
static size_t allocations=0, frees=0, live=0, refusals=0;
static bool refuse=false;
void *__wrap_calloc(size_t count,size_t size) {
    if (refuse) { refusals++;return NULL; }
    void *p=__real_calloc(count,size);
    if (p) { allocations++;live++; }
    return p;
}
void __wrap_free(void *p) { if (p) { frees++;live--; } __real_free(p); }
int main(void) {
    if (__hepta_cb_fn_probe(7,true)!=30) return 1;
    if (__hepta_cb_fn_probe(13,false)!=19) return 2;
    refuse=true;
    if (__hepta_cb_fn_probe(65519,true)!=1001) return 3;
    refuse=false;
    if (__hepta_cb_fn_probe(17,true)!=40) return 4;
    if (__hepta_cb_fn_probe(SIZE_MAX,true)!=1001) return 5;
    if (__hepta_cb_fn_probe(0,true)!=23) return 6;
    printf("%zu %zu %zu %zu\n",allocations,frees,live,refusals);
    return allocations!=3 || frees!=3 || live!=0 || refusals!=1;
}
