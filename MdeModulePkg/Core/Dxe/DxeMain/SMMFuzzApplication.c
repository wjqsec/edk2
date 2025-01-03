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
UINT8 *CommData;

typedef struct _SMI_HANDLER_GROUP {
  UINTN NumModules;
  UINTN NumSmiHandlers;
  GUID Handlers[20];
}SMI_HANDLER_GROUP;

UINTN NumGroups;
SMI_HANDLER_GROUP Groups[50];

UINT32 SmiFuzzTimes[200] = {0};
SMM_MODULES_HANDLER_PROTOCOL_INFO *ReportDataBackup;


struct _SMI_HANDLER_LIST {
  UINTN NumSmiHandlers;
  GUID Handlers[200];
} SmiHandlers;

VOID PrintSmmReport(
  SMM_MODULES_HANDLER_PROTOCOL_INFO *Report
  )
{
    DEBUG((DEBUG_INFO,"SMRAM: %p %p %x %x\n",Report->CpuStart, Report->PhysicalStart, Report->PhysicalSize,sizeof(SMM_MODULES_HANDLER_PROTOCOL_INFO)));

    for(int i = 0 ; i < Report->NumModules; i++)
    {
      DEBUG((DEBUG_INFO,"smm module: %g %p %x\n",&Report->info[i].Guid,Report->info[i].ImageBase,Report->info[i].ImageSize));
      for(int j = 0; j < Report->info[i].NumSmiHandlers; j++)
      {
        DEBUG((DEBUG_INFO,"  smi handler: %g\n",&Report->info[i].SmiHandlers[j]));
      }
      for(int j = 0; j < Report->info[i].NumProduceProtocols; j++)
      {
        DEBUG((DEBUG_INFO,"  produce protocol: %g\n",&Report->info[i].ProduceProtocols[j]));
      }
      for(int j = 0; j < Report->info[i].NumConsumeProtocols; j++)
      {
        DEBUG((DEBUG_INFO,"  consume protocol: %g\n",&Report->info[i].ConsumeProtocols[j]));
      }
    }
    for(int i = 0 ; i < Report->NumUnclassifiedSmiHandlers; i++)
    {
      DEBUG((DEBUG_INFO,"unclassified smi handler: %g\n",&Report->UnclassifiedSmiHandlers[i]));
    }
    DEBUG((DEBUG_INFO,"%d root handlers found\n",Report->NumRootSmiHandlers));
    for(int i = 0 ; i < Report->NumNonLoadedModules; i++)
    {
      DEBUG((DEBUG_INFO, "nonloaded smm module: %g\n",&Report->NonLoadedModules[i]));
    }
}


EFI_STATUS GetSmmCommBuffer(UINTN  MinimalSizeNeeded)
{
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
  for (Index = 0; Index < PiSmmCommunicationRegionTable->NumberOfEntries; Index++) {
    if (Entry->Type == EfiConventionalMemory) {
      Size = EFI_PAGES_TO_SIZE ((UINTN)Entry->NumberOfPages);
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
  CopyGuid(&SmiHandlers.Handlers[SmiHandlers.NumSmiHandlers++], &gEfiSmmFuzzRootGuid);
  for (UINTN i = 0; i < ReportDataBackup->NumModules; i++) {
    for (UINTN j = 0; j < ReportDataBackup->info[i].NumSmiHandlers; j++) {
      SmiHandlers.Handlers[SmiHandlers.NumSmiHandlers++] = ReportDataBackup->info[i].SmiHandlers[j];
    }
  }
}
UINTN FindSmiHandlerIndex(GUID *Guid) {
  for (UINTN i = 0; i < SmiHandlers.NumSmiHandlers; i++) {
    if (CompareGuid(&SmiHandlers.Handlers[i], Guid)) {
      return i;
    }
  }
  LIBAFL_QEMU_END(LIBAFL_QEMU_END_UNKNOWN,0,0);
  return 0;
}


VOID InsertModuleSmiToGroup(SMI_HANDLER_GROUP *Group, SMM_MODULE_HANDLER_PROTOCOL_INFO **Dep) {
  for(UINTN i = 0 ; i < (*Dep)->NumSmiHandlers; i++) {
    CopyGuid(&Group->Handlers[Group->NumSmiHandlers++], &(*Dep)->SmiHandlers[i]);
  }
  if ((*Dep)->NumSmiHandlers > 0)
    Group->NumModules++;
}

EFI_STATUS GroupSmiHandlers() 
{
  SMM_MODULES_HANDLER_PROTOCOL_INFO *ReportData;
  EFI_STATUS Status;
  ReportData = (SMM_MODULES_HANDLER_PROTOCOL_INFO*)CommData;
  Status = SmmCall(&gEfiSmmReportSmmModuleInfoGuid, sizeof(SMM_MODULES_HANDLER_PROTOCOL_INFO));
  if (EFI_ERROR(Status)) {
      DEBUG((DEBUG_INFO,"Error: Unable to call gEfiSmmReportSmmModuleInfoGuid. %r\n",Status));
      return Status;
  }
  CopyMem (ReportDataBackup,ReportData,sizeof(SMM_MODULES_HANDLER_PROTOCOL_INFO));



  NumGroups = 0;
  Groups[NumGroups].NumSmiHandlers = 1;
  CopyGuid(&Groups[NumGroups].Handlers[0], &gEfiSmmFuzzRootGuid);
  NumGroups++;
  for (UINTN i = 0; i < ReportDataBackup->NumModules; i++) {
    if (ReportDataBackup->info[i].NumSmiHandlers == 0) 
      continue;
    UINTN NumDep;
    SMM_MODULE_HANDLER_PROTOCOL_INFO **Dep = CollectModuleDependency(ReportDataBackup, &ReportDataBackup->info[i], &NumDep);
    Groups[NumGroups].NumSmiHandlers = 0;
    Groups[NumGroups].NumModules = 0;
    for (UINTN j = 0; j < NumDep; j++) {
      InsertModuleSmiToGroup(&Groups[NumGroups], &Dep[j]);
    }
    NumGroups++;
  }
  return Status;
}

VOID ReportSmmModuleInfo() {
  for (UINTN i = 0; i < ReportDataBackup->NumModules; i++) {
    LIBAFL_QEMU_SMM_REPORT_SMM_MODULE_INFO((UINTN)&ReportDataBackup->info[i].Guid, (UINTN)ReportDataBackup->info[i].ImageBase, (UINTN)ReportDataBackup->info[i].ImageBase + (UINTN)ReportDataBackup->info[i].ImageSize);   
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
VOID ReportCommDataAddr() {
  LIBAFL_QEMU_SMM_REPORT_COMMBUF_INFO((UINTN)CommData,sizeof(SMM_MODULES_HANDLER_PROTOCOL_INFO));
}
VOID ReportSmiInfo() {
  for (UINTN i = 0; i < SmiHandlers.NumSmiHandlers; i++) {
    LIBAFL_QEMU_SMM_REPORT_SMI_INFO(i, (UINTN)&SmiHandlers.Handlers[i]);
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
    
  DEBUG((DEBUG_INFO,"start SmmFuzzMain\n"));

  EFI_STATUS Status;
  
  UINTN  MinimalSizeNeeded = sizeof(SMM_MODULES_HANDLER_PROTOCOL_INFO);

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
    
  ReportDataBackup = AllocatePool(sizeof(SMM_MODULES_HANDLER_PROTOCOL_INFO));
  UINT8 *SmiFuzzSeq = AllocatePool(1024);
  GroupSmiHandlers();
  CollectHandlers();
  

  

  LIBAFL_QEMU_END(LIBAFL_QEMU_END_SMM_MODULE_START,0,0);
  ReportSmmModuleInfo();
  ReportSmmGroupInfo();
  ReportSmiInfo();
  LIBAFL_QEMU_SMM_REPORT_DUMMY_MEM((libafl_word)ReportDataBackup->DummyAddr);
  LIBAFL_QEMU_SMM_REPORT_SMI_SELECT_INFO((UINTN)SmiFuzzSeq,1024);
  
  


  DEBUG((DEBUG_INFO,"Fuzz Data Report End\n"));

  LIBAFL_QEMU_END(LIBAFL_QEMU_END_SMM_FUZZ_START,0,0);
  ZeroMem (SmiFuzzTimes, sizeof (SmiFuzzTimes));
  
  UINTN SmiFuzzSeqSz = LIBAFL_QEMU_SMM_GET_SMI_SELECT_FUZZ_DATA();
  for (UINTN i = 0; i < SmiFuzzSeqSz; i++) {
    UINTN index = SmiFuzzSeq[i];
    if (index == 0) {
      SmmCall(&SmiHandlers.Handlers[index], 0);
    } else {
      UINTN Sz = LIBAFL_QEMU_SMM_GET_COMMBUF_FUZZ_DATA(index, SmiFuzzTimes[index]);
      if (Sz < sizeof(SMM_MODULES_HANDLER_PROTOCOL_INFO))
        SmmCall(&SmiHandlers.Handlers[index], Sz);
    }
    SmiFuzzTimes[index]++;
  } 
  LIBAFL_QEMU_END(LIBAFL_QEMU_END_SMM_FUZZ_END,0,0);
  GroupSmiHandlers();
  ReportSmmGroupInfo();
  LIBAFL_QEMU_END(LIBAFL_QEMU_END_SMM_FUZZ_END,0,0);
  
  
  
  // UINTN SmiFuzzSeqSz;
  // UINTN FuzzGroupIndex;
  // UINTN Sz;
  // UINTN SmiFuzzIndex;
  // FuzzGroupIndex = LIBAFL_QEMU_SMM_GET_SMI_GROUP_INDEX_FUZZ_DATA() % NumGroups;

  // if (FuzzGroupIndex == 0) {
  //   SmmCall(&Groups[FuzzGroupIndex].Handlers[0], 0);
  // } else {
  //   SmiFuzzSeqSz = LIBAFL_QEMU_SMM_GET_SMI_SELECT_FUZZ_DATA();
  //   for (UINTN i = 0; i < SmiFuzzSeqSz; i++) {
  //     SmiFuzzIndex = SmiFuzzSeq[i] % Groups[FuzzGroupIndex].NumSmiHandlers;
  //     Sz = LIBAFL_QEMU_SMM_GET_COMMBUF_FUZZ_DATA(SmiFuzzIndex, SmiFuzzTimes[SmiFuzzIndex]);
  //     if (Sz < sizeof(SMM_MODULES_HANDLER_PROTOCOL_INFO)) {
  //       SmmCall(&Groups[FuzzGroupIndex].Handlers[SmiFuzzIndex], Sz);
  //     } 
  //     SmiFuzzTimes[SmiFuzzIndex]++;
  //     (VOID)Sz;
  //   } 
  // }
  // LIBAFL_QEMU_END(LIBAFL_QEMU_END_SMM_FUZZ_END,0,0);
  return EFI_SUCCESS;
}