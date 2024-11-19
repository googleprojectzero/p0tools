/*
Copyright 2024 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>

#include "loader.h"

#define SURFACE_HEIGHT 256
#define SURFACE_WIDTH 256

std::unordered_set<void *> pool_allocations;

void *malloc_pool(size_t size) {
  void *ret = malloc(size);
  // void *ret = calloc(1, size);
  // printf("malloc_pool allocated at %p\n", ret);
  pool_allocations.insert(ret);
  return ret;
}

void *calloc_pool(size_t size) {
  void *ret = calloc(1, size);
  // printf("malloc_pool allocated at %p\n", ret);
  pool_allocations.insert(ret);
  return ret;
}

void free_pool(void *a) {
  std::unordered_set<void *>::iterator iter = pool_allocations.find(a);
  if(iter == pool_allocations.end()) {
    printf("Free of unknown allocation, crashing\n");
    *(uint8_t *)0xdeaddeaddead = 1;
  }
  free(*iter);
  pool_allocations.erase(iter);
}

void free_all_pool() {
  for(std::unordered_set<void *>::iterator iter = pool_allocations.begin(); iter != pool_allocations.end(); iter++) {
    free(*iter);
  }
  pool_allocations.clear();
}

uint32_t decoder_config[4];

void __attribute__ ((noinline)) replacement_bzero(void *s, size_t n) {
  printf("In bzero %p %zd\n", s, n);
  memset(s, 0, n);
  return;
}

void* replacement_memmove(void* destination, const void* source, size_t num) {
  return memmove(destination, source, num);
}

int replacement_memcmp(const void* ptr1, const void* ptr2, size_t num) {
  return memcmp(ptr1, ptr2, num);
}

void * __attribute__ ((noinline)) replacement_iomalloctypeimpl(void *type_descriptor) {
  uint32_t size = *(uint32_t *)((char *)type_descriptor + 0x2c);
  void *ret = calloc_pool(size);

  printf("In IoMallocTypeImpl, size: %u, address: %p\n", size, ret);
  return ret;
}

void * __attribute__ ((noinline)) replacement_iomalloctypevarimpl(void *type_descriptor, size_t size) {
  void *ret = calloc_pool(size);
  printf("In IoMallocTypeVarImpl, size: %zu, address: %p\n", size, ret);
  return ret;
}

void * __attribute__ ((noinline)) replacement_osobjecttypednew(void *type_descriptor, size_t size) {
  void *ret = calloc_pool(size);
  printf("In OSObject_typed_operator_new, size: %zu, address: %p\n", size, ret);
  return ret;
}

void __attribute__ ((noinline)) replacement_osloginternal(void *dso, uint64_t log, uint64_t type, const char *message, ...) {
  printf("In os_log_internal: ");
  va_list argptr;
  va_start(argptr, message);
  vfprintf(stdout, message, argptr);
  va_end(argptr);
  printf("\n");
}

uint64_t __attribute__ ((noinline)) replacement_avduserclientallocate(void *client, uint64_t *in, uint64_t *out) {
  uint32_t type = ((uint32_t *)in)[5];

  
  if(type == 3) {
    memset(out, 0xbb, 134);
    out[0] = in[3];
    uint32_t alloc_size = SURFACE_HEIGHT * SURFACE_WIDTH * 4;
    void *allocation = malloc_pool(alloc_size);
    out[1] = (uint64_t)allocation;
    out[2] = (uint64_t)allocation;
    printf("In AppleAVDUserClient::allocateMemory, type: %d, ret: %p\n", type, allocation);
    *(uint32_t *)((uint8_t *)out + 52) = 0;
    *(uint32_t *)((uint8_t *)out + 56) = 0;
    *(uint32_t *)((uint8_t *)out + 68) = SURFACE_WIDTH * 4;
    *(uint32_t *)((uint8_t *)out + 72) = SURFACE_WIDTH * 4;
    *(uint32_t *)((uint8_t *)out + 92) = SURFACE_HEIGHT;
    *(uint32_t *)((uint8_t *)out + 96) = SURFACE_HEIGHT;
    *(uint32_t *)((uint8_t *)out + 84) = SURFACE_WIDTH;
    *(uint32_t *)((uint8_t *)out + 88) = SURFACE_WIDTH;
    *(uint32_t *)((uint8_t *)out + 100) = SURFACE_HEIGHT * SURFACE_WIDTH * 4;
    *(uint32_t *)((uint8_t *)out + 104) = SURFACE_HEIGHT * SURFACE_WIDTH * 4;
    *(uint32_t *)((uint8_t *)out + 116) = 0x00000020; // pixel format
    *(uint8_t *)((uint8_t *)out + 124) = 0;
    *(uint8_t *)((uint8_t *)out + 125) = 0;
   
    *(uint32_t *)((uint8_t *)out + 44) = alloc_size;
    *(uint32_t *)((uint8_t *)out + 48) = alloc_size;
    *(uint32_t *)((uint8_t *)out + 128) = ((uint32_t *)in)[4];
    *(uint32_t *)((uint8_t *)out + 132) = ((uint32_t *)in)[5];
  } else {
    uint64_t size = in[1];
    void *ret = malloc_pool(size);
    printf("In AppleAVDUserClient::allocateMemory, type: %d, size: %lld, ret: %p\n", type, size, ret);
    memset(out, 0xaa, 134);
    //out[0] = (uint64_t)ret;
    out[1] = (uint64_t)ret;
    out[2] = (uint64_t)ret;
  }

  void *tmp = malloc_pool(0x40);
  memset(tmp, 0xcc, 0x40);
  *(void **)((uint8_t *)out + 32) = tmp;

  return 0;
}

uint64_t __attribute__ ((noinline)) replacement_avduserclientdeallocate() {
  return 0;
}


void __attribute__ ((noinline)) getwidthandheight(void *client, uint32_t *width, uint32_t *height) {
  *width = decoder_config[0];
  *height = decoder_config[1];
}

void __attribute__ ((noinline)) getlumadepthminus8(void *client, uint32_t *depth) {
  *depth = decoder_config[2];
}

void __attribute__ ((noinline)) getchromaformat(void *client, uint32_t *format) {
  *format = decoder_config[3];
}

uint64_t __attribute__ ((noinline)) sendcommandtocommandgate() {
  printf("In sendCommandToCommandGate\n");
  return 0;
}

uint64_t __attribute__ ((noinline)) waitforclientspandingcommands() {
  return 0;
}

void __attribute__ ((noinline)) replacement_kerneldebug() {
}

void __attribute__ ((noinline)) replacement_releasedisplaybuffer() {
}

uint64_t __attribute__ ((noinline)) replacement_iosurface_setdataproperty() {
  return 0;
}


int64_t replacement_getdecodebufinframeparamq(void *a1, uint8_t **a2, int32_t *a3, uint32_t *a4, uint64_t a5) {
  *a2 = (uint8_t *)malloc_pool(198144);
  *a3 = 0;
  *a4 = 0;
  return 0;
}

bool __attribute__ ((noinline)) replacement_test(uint8_t *a1, uint64_t a2, uint64_t *a3, int a4) {
  printf("In getrendertarget\n");
  uint64_t *arr1, *arr2;
  arr1 = (uint64_t *)(a1 + 24);
  arr2 = (uint64_t *)(a1 + 1056);
  for(int i=0; i<=128; i++) {
    printf("%d  %llx  %llx\n", i, arr1[i], arr2[i]);
  }
  *a3 = 0xcccccccccccccccc;
  return true;
}


typedef void (*t_CAVDAvxDecoder_constructor)(void *, void *, unsigned, bool);
t_CAVDAvxDecoder_constructor CAVDAvxDecoder_constructor;

typedef int64_t (*t_CAVDAvxDecoder_VAStartDecode)(void *, const char *, int);
t_CAVDAvxDecoder_VAStartDecode CAVDAvxDecoder_VAStartDecode;

typedef int64_t (*t_CAVDAvxDecoder_VADecodeFrame)(void *, const char *, int, int, int, int, int, void *);
t_CAVDAvxDecoder_VADecodeFrame CAVDAvxDecoder_VADecodeFrame;

typedef int64_t (*t_CAVDDecoder_VAMapPixelBuffer)(void *, uint32_t, uint64_t, uint64_t, uint64_t, uint64_t);
t_CAVDDecoder_VAMapPixelBuffer CAVDDecoder_VAMapPixelBuffer;

typedef int64_t (*t_AppleAVD_allocateKernelMemory)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
t_AppleAVD_allocateKernelMemory AppleAVD_allocateKernelMemory;



// shared memory stuff

#include <sys/mman.h>
#include <fcntl.h>

#define MAX_SAMPLE_SIZE 1000000
#define SHM_SIZE (4 + MAX_SAMPLE_SIZE)
unsigned char *shm_data;

bool use_shared_memory;

int setup_shmem(const char *name)
{
  int fd;

  // get shared memory file descriptor (NOT a file)
  fd = shm_open(name, O_RDONLY, S_IRUSR | S_IWUSR);
  if (fd == -1)
  {
    printf("Error in shm_open\n");
    return 0;
  }

  // map shared memory to process address space
  shm_data = (unsigned char *)mmap(NULL, SHM_SIZE, PROT_READ, MAP_SHARED, fd, 0);
  if (shm_data == MAP_FAILED)
  {
    printf("Error in mmap\n");
    return 0;
  }

  return 1;
}



void __attribute__ ((noinline)) fuzz(char *name) {
  char *sample_bytes = NULL;
  uint32_t sample_size = 0;
  
  // read the sample either from file or
  // shared memory
  if(use_shared_memory) {
    sample_size = *(uint32_t *)(shm_data);
    if(sample_size > MAX_SAMPLE_SIZE) sample_size = MAX_SAMPLE_SIZE;
    sample_bytes = (char *)malloc(sample_size);
    memcpy(sample_bytes, shm_data + sizeof(uint32_t), sample_size);
  } else {
    FILE *fp = fopen(name, "rb");
    if(!fp) {
      printf("Error opening %s\n", name);
      return;
    }
    fseek(fp, 0, SEEK_END);
    sample_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    sample_bytes = (char *)malloc(sample_size);
    fread(sample_bytes, 1, sample_size, fp);
    fclose(fp);
  }
  char *sample_bytes_start = sample_bytes;
  
  // void *avd_user_client = calloc(1, 9112);

  if(sample_size >= (sizeof(decoder_config) + 1)) {
    memcpy(decoder_config, sample_bytes, sizeof(decoder_config));
    sample_bytes += sizeof(decoder_config);
    sample_size -= sizeof(decoder_config);
  } else {
    if(sample_bytes_start) free(sample_bytes_start);
    return;
  }
  
  // todo diffent decoders can be used here
  int device_type = 404; // 417
  
  void *avx_decoder = calloc_pool(0x33C0);
  
  void *avduserclient = calloc_pool(0x2398);
  void *avd = calloc_pool(0x14990);
  *(void **)((char *)avduserclient + 216) = avd;
  
  CAVDAvxDecoder_constructor(avx_decoder, avduserclient, device_type, false);

  CAVDDecoder_VAMapPixelBuffer(avx_decoder, 0, 0x1234, 0, 0, 0);
  CAVDDecoder_VAMapPixelBuffer(avx_decoder, 0, 0x12345, 1, 0, 0);

  printf("###### Decode start ######\n");

  int64_t ret = CAVDAvxDecoder_VAStartDecode(avx_decoder, sample_bytes, sample_size);
  
  printf("VAStartDecode returned %lld\n", ret);

  void *seq_params = calloc_pool(256);
  int frameno = 0;
  while(!ret) {
    // figure out how much bytes were processed
    uint64_t *av1_syntax = *((uint64_t **)avx_decoder + 1574);
    int64_t bytes_processed = av1_syntax[2] - (int64_t)(sample_bytes);
    
    if((bytes_processed < 0) || (bytes_processed > sample_size)) {
      printf("Error getting sample position\n");
      break;
    }
    
    if(bytes_processed == sample_size) {
      break;
    }
    
    sample_bytes += sizeof(bytes_processed);
    sample_size -= sizeof(bytes_processed);

    printf("###### Decode frame ######\n");
    
    ret = CAVDAvxDecoder_VADecodeFrame(avx_decoder, sample_bytes, sample_size, frameno, 0, 0, 0, seq_params);
    
    frameno++;
    if(frameno == 5) break;
  }
  
  printf("###### Decode end ######\n");
  
  free_all_pool();
  
  if(sample_bytes_start) free(sample_bytes_start);
}


int main(int argc, char **argv) {
  if(argc < 4) {
    printf("Usage: %s <avd> <-f|-m> <filename>\n", argv[0]);
    return 0;
  }
  
  std::unordered_map<uint64_t, uint64_t> address_replacements;
  // needed if ony AppleAVD is loaded and not the full kernel cache
  // address_replacements[0xab08520c00] = (uint64_t)&replacement_bzero;
  // address_replacements[0xab08520a50] = (uint64_t)&replacement_memmove;
  // address_replacements[0xab085237e0] = (uint64_t)&replacement_memcmp;
  // address_replacements[0xab08c2e540] = (uint64_t)&replacement_iomalloctypeimpl;
  // address_replacements[0xab08c2eed4] = (uint64_t)&replacement_iomalloctypevarimpl;
  // address_replacements[0xab08c065e8] = (uint64_t)&replacement_osloginternal;
  // address_replacements[0xab08bb63d8] = (uint64_t)&replacement_osobjecttypednew;
  // address_replacements[0xab08a27934] = (uint64_t)&replacement_kerneldebug;
  // address_replacements[0xab0ae30088] = (uint64_t)&replacement_iosurface_setdataproperty;

  std::unordered_map<std::string, uint64_t> symbol_replacements;

  
  symbol_replacements["_IOMallocTypeImpl"] = (uint64_t)&replacement_iomalloctypeimpl;
  symbol_replacements["_IOMallocTypeVarImpl"] = (uint64_t)&replacement_iomalloctypevarimpl;
  symbol_replacements["__os_log_internal"] = (uint64_t)&replacement_osloginternal;
  symbol_replacements["_OSObject_typed_operator_new"] = (uint64_t)&replacement_osobjecttypednew;
  symbol_replacements["_kernel_debug"] = (uint64_t)&replacement_osobjecttypednew;
  symbol_replacements["__ZN9IOSurface15setDataPropertyEymPKv_0"] = (uint64_t)&replacement_iosurface_setdataproperty;

  symbol_replacements["__ZN18AppleAVDUserClient17getWidthAndHeightEPjS0_"] = (uint64_t)&getwidthandheight;
  symbol_replacements["__ZN18AppleAVDUserClient18getLumaDepthMinus8EPj"] = (uint64_t)&getlumadepthminus8;
  symbol_replacements["__ZN18AppleAVDUserClient15getChromaFormatEPj"] = (uint64_t)&getchromaformat;
  symbol_replacements["__ZN8AppleAVD24sendCommandToCommandGateEP8sPQEntry17eAppleAvdCmdTypes"] = (uint64_t)&sendcommandtocommandgate;
  symbol_replacements["__ZN8AppleAVD35waitForClientsPendingCommands_DelayEj"] = (uint64_t)&waitforclientspandingcommands;
  symbol_replacements["__ZN18AppleAVDUserClient14allocateMemoryEP26_sAppleAVDAllocateMemoryInP27_sAppleAVDAllocateMemoryOut"] = (uint64_t)&replacement_avduserclientallocate;
  symbol_replacements["__ZN18AppleAVDUserClient16deallocateMemoryEP28_sAppleAVDDeallocateMemoryInP29_sAppleAVDDeallocateMemoryOut"] = (uint64_t)&replacement_avduserclientdeallocate;
  symbol_replacements["__ZN18AppleAVDUserClient46decodeFrameFigHelper_GetDecodeBufInFrameParamQEPPhPiPji"] = (uint64_t)&replacement_getdecodebufinframeparamq;
  symbol_replacements["__ZN14CAVDAvxDecoder20ReleaseDisplayBufferEP16av1_frame_buffer"] = (uint64_t)&replacement_releasedisplaybuffer;

  void *load_address = load(argv[1], true, address_replacements, symbol_replacements);
  if(!load_address) {
    printf("Error loading module\n");
    return 0;
  }
  printf("Loaded at %p\n", load_address);
  
  CAVDAvxDecoder_constructor = (t_CAVDAvxDecoder_constructor)(get_symbol_address("__ZN14CAVDAvxDecoderC2EPvjb"));
  CAVDAvxDecoder_VAStartDecode = (t_CAVDAvxDecoder_VAStartDecode)(get_symbol_address("__ZN14CAVDAvxDecoder13VAStartDecodeEPhi"));
  CAVDAvxDecoder_VADecodeFrame = (t_CAVDAvxDecoder_VADecodeFrame)(get_symbol_address("__ZN14CAVDAvxDecoder13VADecodeFrameEPhiiiiiP14avd_seq_params"));
  CAVDDecoder_VAMapPixelBuffer = (t_CAVDDecoder_VAMapPixelBuffer)(get_symbol_address("__ZN11CAVDDecoder16VAMapPixelBufferEijjbyy"));
  AppleAVD_allocateKernelMemory = (t_AppleAVD_allocateKernelMemory)(get_symbol_address("__ZN8AppleAVD20allocateKernelMemoryEjm11eAvdMemType11eAvdMapTypeP4taskP20_avd_client_mem_infobbyyj"));
  
  if(!strcmp(argv[2], "-m")) {
    use_shared_memory = true;
  } else if(!strcmp(argv[2], "-f")) {
    use_shared_memory = false;
  } else {
    printf("Usage: %s <-f|-m> <file or shared memory name>\n", argv[0]);
    return 0;
  }

  // map shared memory here as we don't want to do it
  // for every operation
  if(use_shared_memory) {
    if(!setup_shmem(argv[3])) {
      printf("Error mapping shared memory\n");
    }
  }

  fuzz(argv[3]);

  return 0;
}
