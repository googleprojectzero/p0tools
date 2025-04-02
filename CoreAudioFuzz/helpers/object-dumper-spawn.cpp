#include <stdio.h>
#include <inttypes.h>
#include <stdbool.h>
#include "tinyinst.h"
#include "helpers/load_library.h"

// Structures
struct HALSObjectInfoItem {
  uint64_t object_type;
  void* object;
  uint64_t object_id;
};

struct HALSObjectInfoList {
  void *first_item;
  void *last_item;
};

// Class definition
class ObjectDumperInst : public HookBeginEnd {
public:
  ObjectDumperInst() : HookBeginEnd("CoreAudio", "_AudioHardwareStartServer", 0, CALLCONV_DEFAULT) {}
  void DumpObject(void *object, uint64_t object_id);
  void DumpMemory(void* basePtr, size_t offset);
  void OnFunctionReturned() override;
private:
  std::set<void *> allocations;
};

// Constructor definition
ObjectDumperInst::ObjectDumperInst() {
  allocations
  RegisterHook();
}

// Method definitions
void ObjectDumperInst::DumpObject(void *object, uint64_t object_id) {
  if (!object) {
    printf("Returned object is null.\n");
    return;
  }

  const size_t objectTypeOffset = 28;
  const size_t objectSubTypeOffset = 32;
  char objectType[5] = {0};
  char objectSubType[5] = {0};

  RemoteRead((void*)((uintptr_t)object + objectTypeOffset), objectType, 4);
  RemoteRead((void*)((uintptr_t)object + objectSubTypeOffset), objectSubType, 4);

  // const size_t offset68 = 0x68;
  // void* valueAtOffset68 = nullptr;
  // RemoteRead((void*)((uintptr_t)object + offset68), &valueAtOffset68, sizeof(valueAtOffset68));

  // if ((uintptr_t)valueAtOffset68 >= 0x00007f0000000000 && (uintptr_t)valueAtOffset68 <= 0x7fffffffffff) {
  //   return;
  // }

  printf("\n************ OBJECT DUMP ***************\n");
  printf("Object ID: %d\n", object_id);
  printf("Object Type (offset 28): %.4s\n", objectType);
  printf("Object SubType (offset 32): %.4s\n", objectSubType);

  printf("Raw memory contents at offset 0x0 of object:\n");
  DumpMemory(object, 0x0);

  // printf("Raw memory contents at offset 0x68 of object:\n");
  // DumpMemory(object, 0x68);
}

void ObjectDumperInst::DumpMemory(void* basePtr, size_t offset) {
  void* targetPtr = (void*)((uintptr_t)basePtr + offset);
  const size_t dumpSize = 0x120;
  uint8_t buffer[dumpSize];

  RemoteRead(targetPtr, buffer, dumpSize);

  printf("Memory dump at %p:\n", targetPtr);
  for (size_t i = 0; i < dumpSize; i += 16) {
    printf("%08zX: ", (size_t)targetPtr + i); // Corrected format specifier
    char ascii[17] = {0};
    for (size_t j = 0; j < 16; ++j) {
      if (i + j < dumpSize) {
        uint8_t byte = buffer[i + j];
        printf("%02X ", byte);
        ascii[j] = (byte >= 32 && byte <= 126) ? (char)byte : '.';
      } else {
        printf("   ");
      }
    }
    printf(" |%s|\n", ascii);
  }
  printf("\n");
}

void ObjectDumperInst::OnModuleInstrumented(ModuleInfo *module) {
  printf("OnModuleInstrumented: Looks like we made it!\n");

  // ModuleInfo *coreaudio_module = GetModuleByName("CoreAudio");
  // if (!coreaudio_module) {
  //   printf("Failed to locate CoreAudio module.\n");
  //   return;
  // }

  // printf("Getting base address\n");

  void *base_address = (void *)module->module_header;

  printf("base address: %d\n", base_address);

  void *sObjectInfo_address_ptr = GetSymbolAddress(base_address, "__ZN14HALS_ObjectMap15sObjectInfoListE");

  if (!sObjectInfo_address_ptr) {
    printf("Failed to locate sObjectInfoList symbol.\n");
    return;
  }

  void *sObjectInfo_address;
  RemoteRead(sObjectInfo_address_ptr, &sObjectInfo_address, sizeof(void *));

  HALSObjectInfoList sObjectInfoList;
  RemoteRead(sObjectInfo_address, &sObjectInfoList, sizeof(sObjectInfoList));

  printf("sObjectInfoList located at %p\n", sObjectInfo_address);
  printf("First item: %p, Last item: %p\n", sObjectInfoList.first_item, sObjectInfoList.last_item);


  void *current_item = sObjectInfoList.first_item;
  while (current_item < sObjectInfoList.last_item) {
    HALSObjectInfoItem objectInfo;
    RemoteRead(current_item, &objectInfo, sizeof(objectInfo));

    printf("Got object with ID: %d\n", objectInfo.object_id);

    // DumpObject(current_item);

    DumpObject(objectInfo.object, objectInfo.object_id);
    current_item = (void*)((uint8_t *)current_item + sizeof(HALSObjectInfoItem));
  }

  printf("Completed iterating through sObjectInfoList.\n");
}

int main(int argc, char **argv) {
  ObjectDumperInst *instrumentation = new ObjectDumperInst();
  instrumentation->Init(argc, argv);

  int target_opt_ind = 0;
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--") == 0) {
      target_opt_ind = i + 1;
      break;
    }
  }

  int target_argc = (target_opt_ind) ? argc - target_opt_ind : 0;
  char **target_argv = (target_opt_ind) ? argv + target_opt_ind : NULL;

  unsigned int pid = GetIntOption("-pid", argc, argv, 0);

  if (!target_argc && !pid) {
    printf("Usage:\n%s <options> -- <target command line>\nOr:\n%s <options> -pid <pid to attach to>\n", argv[0], argv[0]);
    return 0;
  }

  DebuggerStatus status;
  if (target_argc) {
    status = instrumentation->Run(target_argc, target_argv, 0xFFFFFFFF);
  } else {
    status = instrumentation->Attach(pid, 0xFFFFFFFF);
  }

  switch (status) {
    case DEBUGGER_CRASHED:
      printf("Process crashed\n");
      instrumentation->Kill();
      break;
    case DEBUGGER_HANGED:
      printf("Process hanged\n");
      instrumentation->Kill();
      break;
    case DEBUGGER_PROCESS_EXIT:
      printf("Process exited normally\n");
      break;
    default:
      printf("Unexpected status received from the debugger\n");
      break;
  }

  delete instrumentation;
  return 0;
}
