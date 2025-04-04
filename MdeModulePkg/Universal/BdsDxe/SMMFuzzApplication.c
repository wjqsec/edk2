#include <Protocol/SmmCommunication.h>
#include <Library/BaseMemoryLib.h>
#include <Core/PiSmmCore/PiSmmCore.h>
#include <Guid/MemoryProfile.h>
#include <Guid/PiSmmCommunicationRegionTable.h>
#include <Guid/GlobalVariable.h>
#include <Protocol/Cpu.h>
#include <Uefi/UefiBaseType.h>
#include <Uefi.h>
#include <Library/PrintLib.h>
#include <Guid/DxeServices.h>
#include <Base.h>
#include <Library/PeCoffGetEntryPointLib.h>
#include <Library/SerialPortLib.h>
#include <Library/SynchronizationLib.h>
#include <Protocol/SmmBase2.h>
#include <Register/Intel/Cpuid.h>
#include <Register/Intel/Msr.h>
#include "PiDxe.h"
#include <Guid/EventGroup.h>
#include <Protocol/FirmwareVolumeBlock.h>
#include <Protocol/DevicePath.h>
#include <Library/UefiLib.h>
#include <Library/UefiDriverEntryPoint.h>
#include <Library/BaseLib.h>
#include <Library/DxeServicesTableLib.h>
#include <Library/UefiRuntimeLib.h>
#include <Library/DebugLib.h>
#include <Library/HobLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/DevicePathLib.h>
#include "libafl_qemu.h"
#include "SmiFuzz.h"


EFI_SMM_COMMUNICATION_PROTOCOL *SmmCommunication;
EFI_SMM_COMMUNICATE_HEADER *CommHeader;
SMM_FUZZ_GLOBAL_DATA *SmmFuzzGlobalData;
UINT8 *CommData;

typedef struct _SMI_HANDLER_GROUP {
  UINTN NumModules;
  UINTN NumSmiHandlers;
  GUID Handlers[40];
}SMI_HANDLER_GROUP;

UINTN NumGroups;
SMI_HANDLER_GROUP Groups[50];

UINT32 SmiFuzzTimes[200] = {0};
SMM_MODULES_HANDLER_PROTOCOL_INFO *ReportDataBackup;


struct _SMI_HANDLER_LIST {
  UINTN NumSmiHandlers;
  SMI_HANDLER_INFO Handlers[200];
} SmiHandlers;


EFI_STATUS GetSmmCommBuffer(UINTN  MinimalSizeNeeded)
{
  DEBUG((DEBUG_INFO,"GetSmmCommBuffer\n"));
  EDKII_PI_SMM_COMMUNICATION_REGION_TABLE  *PiSmmCommunicationRegionTable;
  EFI_STATUS Status;
  EFI_MEMORY_DESCRIPTOR  *Entry;
  UINTN  Index;
  UINTN  Size;
  Status = EfiGetSystemConfigurationTable (
            &gEdkiiPiSmmCommunicationRegionTableGuid,
            (VOID **)&PiSmmCommunicationRegionTable
            );
  if (EFI_ERROR (Status)) {
    DEBUG((DEBUG_INFO,"Error: Unable to locate gEdkiiPiSmmCommunicationRegionTableGuid. %r\n",Status));
    return Status;
  }
  ASSERT (PiSmmCommunicationRegionTable != NULL);
  
  Entry = (EFI_MEMORY_DESCRIPTOR *)(PiSmmCommunicationRegionTable + 1);
  Size  = 0;
  DEBUG((DEBUG_INFO,"PiSmmCommunicationRegionTable->NumberOfEntries %x\n",PiSmmCommunicationRegionTable->NumberOfEntries));
  for (Index = 0; Index < PiSmmCommunicationRegionTable->NumberOfEntries; Index++) {
    if (Entry->Type == EfiConventionalMemory) {
      Size = EFI_PAGES_TO_SIZE ((UINTN)Entry->NumberOfPages);
      DEBUG((DEBUG_INFO,"SmmCommunicationBuffer %x\n",Size));
      if (Size >= MinimalSizeNeeded + sizeof(EFI_MEMORY_DESCRIPTOR)) {
        break;
      }
    }

    Entry = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)Entry + PiSmmCommunicationRegionTable->DescriptorSize);
  }
  ASSERT (Index < PiSmmCommunicationRegionTable->NumberOfEntries);
  CommHeader = (EFI_SMM_COMMUNICATE_HEADER *)Entry->PhysicalStart;
  CommData = (UINT8 *)CommHeader->Data;
  return Status;
}

EFI_STATUS SmmCall(GUID *ID, UINTN size)
{
  UINTN CommSize;
  EFI_STATUS Status;
  CopyMem (&CommHeader->HeaderGuid, ID, sizeof(GUID));
  CommHeader->MessageLength = size;
  CommSize = size + sizeof(EFI_SMM_COMMUNICATE_HEADER);
  Status = SmmCommunication->Communicate(SmmCommunication,CommHeader,&CommSize);
  if (EFI_ERROR (Status)) {
    return Status;
  }
  return Status;
}

VOID CollectHandlers() {
  // SmiHandlers.Handlers[SmiHandlers.NumSmiHandlers].IsRoot = TRUE;
  // SmiHandlers.Handlers[SmiHandlers.NumSmiHandlers].Addr = NULL;
  // CopyGuid(&SmiHandlers.Handlers[SmiHandlers.NumSmiHandlers++].SmiHandler, &gEfiSmmFuzzRootGuid);
  for (UINTN i = 0; i < ReportDataBackup->NumModules; i++) {
    for (UINTN j = 0; j < ReportDataBackup->info[i].NumSmiHandlers; j++) {
      SmiHandlers.Handlers[SmiHandlers.NumSmiHandlers].Addr = ReportDataBackup->info[i].SmiHandlers[j].Addr;
      SmiHandlers.Handlers[SmiHandlers.NumSmiHandlers].IsRoot = ReportDataBackup->info[i].SmiHandlers[j].IsRoot;
      SmiHandlers.Handlers[SmiHandlers.NumSmiHandlers++].SmiHandler = ReportDataBackup->info[i].SmiHandlers[j].SmiHandler;
    }
  }
}
UINTN FindSmiHandlerIndex(GUID *Guid) {
  for (UINTN i = 0; i < SmiHandlers.NumSmiHandlers; i++) {
    if (CompareGuid(&SmiHandlers.Handlers[i].SmiHandler, Guid)) {
      return i;
    }
  }
  LIBAFL_QEMU_END(LIBAFL_QEMU_END_UNKNOWN,0,0);
  return 0;
}


VOID InsertModuleSmiToGroup(SMI_HANDLER_GROUP *Group, SMM_MODULE_HANDLER_PROTOCOL_INFO **Dep) {
  for(UINTN i = 0 ; i < (*Dep)->NumSmiHandlers; i++) {
    CopyGuid(&Group->Handlers[Group->NumSmiHandlers++], &(*Dep)->SmiHandlers[i].SmiHandler);
  }
  if ((*Dep)->NumSmiHandlers > 0)
    Group->NumModules++;
}

EFI_STATUS GroupSmiHandlers() 
{
  SMM_MODULES_HANDLER_PROTOCOL_INFO_ADDR *ReportData;
  EFI_STATUS Status;
  ReportData = (SMM_MODULES_HANDLER_PROTOCOL_INFO_ADDR*)CommData;
  ReportData->addr = ReportDataBackup;
  Status = SmmCall(&gEfiSmmReportSmmModuleInfoGuid, sizeof(SMM_MODULES_HANDLER_PROTOCOL_INFO_ADDR));
  if (EFI_ERROR(Status)) {
      DEBUG((DEBUG_INFO,"Error: Unable to call gEfiSmmReportSmmModuleInfoGuid. %r\n",Status));
      return Status;
  }


  NumGroups = 0;
  // Groups[NumGroups].NumSmiHandlers = 1;
  // CopyGuid(&Groups[NumGroups].Handlers[0], &gEfiSmmFuzzRootGuid);
  // NumGroups++;
  for (UINTN i = 0; i < ReportDataBackup->NumModules; i++) {
    ReportDataBackup->info[i].Visited = FALSE;
  }
  for (UINTN i = 0; i < ReportDataBackup->NumModules; i++) {
    if (ReportDataBackup->info[i].NumSmiHandlers == 0 || ReportDataBackup->info[i].Visited) 
      continue;
    ReportDataBackup->info[i].Visited = TRUE;
    UINTN NumDep;
    SMM_MODULE_HANDLER_PROTOCOL_INFO **Dep = CollectModuleDependency(ReportDataBackup, &ReportDataBackup->info[i], &NumDep);
    Groups[NumGroups].NumSmiHandlers = 0;
    Groups[NumGroups].NumModules = 0;
    for (UINTN j = 0; j < NumDep; j++) {
      Dep[j]->Visited = TRUE;
      InsertModuleSmiToGroup(&Groups[NumGroups], &Dep[j]);
    }
    FreePool(Dep);
    NumGroups++;
  }
  return Status;
}

VOID ReportSmmModuleInfo() {
  for (UINTN i = 0; i < ReportDataBackup->NumModules; i++) {
    LIBAFL_QEMU_SMM_REPORT_SMM_MODULE_INFO((UINTN)&ReportDataBackup->info[i].Guid, (UINTN)ReportDataBackup->info[i].ImageBase, (UINTN)ReportDataBackup->info[i].ImageBase + (UINTN)ReportDataBackup->info[i].ImageSize);   
  }
}
VOID ReportDxeModuleInfo() {
  DXE_MODULE_INFOS *Info = (DXE_MODULE_INFOS *)SmmFuzzGlobalData->dxe_module_info;
  for (UINTN i = 0; i < Info->NumModules; i++) {
    LIBAFL_QEMU_SMM_REPORT_SMM_MODULE_INFO((UINTN)&Info->Modules[i].Guid, (UINTN)Info->Modules[i].StartAddress, (UINTN)Info->Modules[i].StartAddress + (UINTN)Info->Modules[i].Size);   
  }
}
VOID ReportSmmGroupInfo() {
  for (UINTN i = 0; i < NumGroups; i++) {
    for (UINTN j = 0; j < Groups[i].NumSmiHandlers; j++) {
      UINTN Index = FindSmiHandlerIndex(&Groups[i].Handlers[j]);
      LIBAFL_QEMU_SMM_REPORT_SMM_FUZZ_GROUP(i, Index);
    }
  }
}

VOID ReportSmiInfo() {
  for (UINTN i = 0; i < SmiHandlers.NumSmiHandlers; i++) {
    LIBAFL_QEMU_SMM_REPORT_SMI_INFO(i, (UINTN)&SmiHandlers.Handlers[i].SmiHandler, (UINTN)SmiHandlers.Handlers[i].Addr);
  } 
}
VOID ReportSkipModuleInfo() {
  for (UINTN i = 0; i < ReportDataBackup->NumSkipModules; i++) {
    LIBAFL_QEMU_SMM_REPORT_SKIP_MODULE_INFO((UINTN)&ReportDataBackup->SkipModules[i]);
  } 
}
VOID ReportUnloadModuleInfo() {
  for (UINTN i = 0; i < ReportDataBackup->NumUnloadModules; i++) {
    LIBAFL_QEMU_SMM_REPORT_UNLOAD_MODULE_INFO((UINTN)&ReportDataBackup->UnloadModules[i]);
  } 
}
/**
  as the real entry point for the application.

  @param[in] ImageHandle    The firmware allocated handle for the EFI image.
  @param[in] SystemTable    A pointer to the EFI System Table.

  @retval EFI_SUCCESS       The entry point is executed successfully.
  @retval other             Some error occurs when executing this entry point.

**/
EFI_STATUS
EFIAPI
SmmFuzzMain(
    IN EFI_HANDLE ImageHandle,
    IN EFI_SYSTEM_TABLE *SystemTable)
{
  EFI_STATUS Status;
  DEBUG((DEBUG_INFO,"start SmmFuzzMain\n"));

  Status = gBS->LocateProtocol (&gSmmFuzzDataProtocolGuid, NULL, (VOID **)&SmmFuzzGlobalData);
  if (EFI_ERROR(Status)) {
      DEBUG((DEBUG_INFO,"Error: Unable to locate gSmmFuzzDataProtocolGuid. %r\n",Status));
      return Status;
  }

  UINTN  MinimalSizeNeeded = 3 * 0x1000;

  Status = gBS->LocateProtocol(&gEfiSmmCommunicationProtocolGuid, NULL, (void **)&SmmCommunication);
  if (EFI_ERROR(Status)) {
      DEBUG((DEBUG_INFO,"Error: Unable to locate gEfiSmmCommunicationProtocolGuid. %r\n",Status));
      return Status;
  }
  Status = GetSmmCommBuffer(MinimalSizeNeeded);
  if (EFI_ERROR(Status)) {
      DEBUG((DEBUG_INFO,"Error: Unable to get smm comm buffer. %r\n",Status));
      return Status;
  }
  DEBUG((DEBUG_INFO,"Got CommBuffer %p\n",CommHeader));  
  ReportDataBackup = AllocatePool(sizeof(SMM_MODULES_HANDLER_PROTOCOL_INFO));
  ZeroMem (ReportDataBackup, sizeof(SMM_MODULES_HANDLER_PROTOCOL_INFO));
  UINT8 *SmiFuzzSeq = AllocatePool(1024);
  GroupSmiHandlers();
  CollectHandlers();
  

  

  LIBAFL_QEMU_END(LIBAFL_QEMU_END_SMM_MODULE_START,0,0);
  ReportSmmModuleInfo();
  ReportSmmGroupInfo();
  ReportSmiInfo();
  ReportSkipModuleInfo();
  ReportUnloadModuleInfo();
  ReportDxeModuleInfo();
  LIBAFL_QEMU_SMM_REPORT_DUMMY_MEM((libafl_word)ReportDataBackup->DummyAddr);
  LIBAFL_QEMU_SMM_REPORT_REDZONE_BUFFER_ADDR((libafl_word)ReportDataBackup->RedZonePageAddr);
  LIBAFL_QEMU_SMM_REPORT_SMI_SELECT_INFO((UINTN)SmiFuzzSeq,1024);
  LIBAFL_QEMU_SMM_REPORT_COMMBUF_INFO((UINTN)CommData,MinimalSizeNeeded - sizeof(EFI_SMM_COMMUNICATE_HEADER));



  DEBUG((DEBUG_INFO,"Fuzz Data Report End\n"));

  LIBAFL_QEMU_END(LIBAFL_QEMU_END_SMM_FUZZ_START,0,0);
  ZeroMem (SmiFuzzTimes, sizeof (SmiFuzzTimes));
  ZeroMem (CommData, MinimalSizeNeeded - sizeof(EFI_SMM_COMMUNICATE_HEADER));
  UINTN SmiFuzzSeqSz = LIBAFL_QEMU_SMM_GET_SMI_SELECT_FUZZ_DATA();
  DEBUG((DEBUG_INFO,"Select len %d\n",SmiFuzzSeqSz));
  for (UINTN i = 0; i < SmiFuzzSeqSz; i++) {
    UINTN index = SmiFuzzSeq[i];
    DEBUG((DEBUG_INFO,"Select %d\n",index));
    LIBAFL_QEMU_SMM_REPORT_SMI_INVOKE_INFO(index, i);
    // LIBAFL_QEMU_SMM_GET_COMMBUF_FUZZ_DATA(index, SmiFuzzTimes[index]);
    // if (*(UINT64*)CommData == 0x1234567887654321)
    // {
    //   DEBUG((DEBUG_INFO,"CommData is 0x1234567887654321\n"));
    //   LIBAFL_QEMU_END(LIBAFL_QEMU_END_SMM_FUZZ_END,0,0);
    // } else if (*(UINT64*)CommData == 0xdeadbeefdeadbeef) {
    //   DEBUG((DEBUG_INFO,"CommData is not deadbeef\n"));
    //   LIBAFL_QEMU_END(LIBAFL_QEMU_END_SMM_FUZZ_END,0,0);
    // } else {
    //   LIBAFL_QEMU_END(LIBAFL_QEMU_END_SMM_FUZZ_END,0,0);
    // }

    if (SmiHandlers.Handlers[index].IsRoot) {
      SmmCall(&SmiHandlers.Handlers[index].SmiHandler, 0);
    } else {
      UINTN Sz = LIBAFL_QEMU_SMM_GET_COMMBUF_FUZZ_DATA(index, SmiFuzzTimes[index]);
      SmmCall(&SmiHandlers.Handlers[index].SmiHandler, Sz);
      // if (Sz <= (MinimalSizeNeeded - sizeof(EFI_SMM_COMMUNICATE_HEADER))) {
      //   SmmCall(&SmiHandlers.Handlers[index], Sz);
      // } 
    }
    SmiFuzzTimes[index]++;
  } 
  LIBAFL_QEMU_END(LIBAFL_QEMU_END_SMM_FUZZ_END,0,0);
  GroupSmiHandlers();
  ReportSmmGroupInfo();
  LIBAFL_QEMU_END(LIBAFL_QEMU_END_SMM_FUZZ_END,0,0);
  
  return EFI_SUCCESS;
}