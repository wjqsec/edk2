#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Protocol/SmmCommunication.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Core/PiSmmCore/PiSmmCore.h>
#include <Guid/MemoryProfile.h>
#include <Guid/PiSmmCommunicationRegionTable.h>
#include <Protocol/Cpu.h>
#include <Uefi/UefiBaseType.h>
#include <Uefi.h>
#include <Library/PrintLib.h>
#include <Guid/DxeServices.h>
#include <Base.h>
#include <Uefi.h>
#include <Library/PeCoffGetEntryPointLib.h>
#include <Library/SerialPortLib.h>
#include <Library/SynchronizationLib.h>
#include <Library/PrintLib.h>
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
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DevicePathLib.h>
#include "libafl_qemu.h"

UINT8 *CommBuffer;
EFI_SMM_COMMUNICATION_PROTOCOL *SmmCommunication;
EFI_SMM_COMMUNICATE_HEADER *CommHeader;
UINT8 *CommData;
// VOID PrintMemoryMap(VOID) {
//     EFI_MEMORY_DESCRIPTOR *MemoryMap = NULL;
//     UINTN MemoryMapSize = 0;
//     UINTN MapKey;
//     UINTN DescriptorSize;
//     UINT32 DescriptorVersion;
//     EFI_STATUS Status;
    
//     // Call to get the size of memory map
//     Status = gBS->GetMemoryMap(&MemoryMapSize, MemoryMap, &MapKey, &DescriptorSize, &DescriptorVersion);
//     if (Status != EFI_BUFFER_TOO_SMALL) {
//         Print(L"Failed to get memory map size: %r\n", Status);
//         return;
//     }
    
//     // Allocate pool for memory map
//     MemoryMap = AllocatePool(MemoryMapSize);
//     if (MemoryMap == NULL) {
//         Print(L"Failed to allocate memory\n");
//         return;
//     }
    
//     // Get the actual memory map
//     Status = gBS->GetMemoryMap(&MemoryMapSize, MemoryMap, &MapKey, &DescriptorSize, &DescriptorVersion);
//     if (EFI_ERROR(Status)) {
//         Print(L"Failed to get memory map: %r\n", Status);
//         FreePool(MemoryMap);
//         return;
//     }
    
//     // Parse the memory map
//     EFI_MEMORY_DESCRIPTOR *MemDesc;
//     UINTN EntryCount = MemoryMapSize / DescriptorSize;
//     for (UINTN Index = 0; Index < EntryCount; Index++) {
//         MemDesc = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)MemoryMap + (Index * DescriptorSize));
        
//         // Print memory region details
//         Print(L"Type: %d, Physical Start: 0x%lx, Number of Pages: 0x%lx\n",
//               MemDesc->Type, MemDesc->PhysicalStart, MemDesc->NumberOfPages);
//     }
    
//     // Free allocated memory
//     FreePool(MemoryMap);
// }
// VOID PrintMemorySpaceMap() {
//     EFI_STATUS Status;
//     UINTN NumberOfDescriptors;
//     EFI_GCD_MEMORY_SPACE_DESCRIPTOR *MemorySpaceMap = NULL;

//     // Get memory space map
//     Status = gDS->GetMemorySpaceMap(&NumberOfDescriptors, &MemorySpaceMap);
//     if (EFI_ERROR(Status)) {
//         Print(L"GetMemorySpaceMap failed: %r\n", Status);
//         return;
//     }

//     // Print memory space map information
//     Print(L"Memory Layout (GetMemorySpaceMap):\n");
//     for (UINTN Index = 0; Index < NumberOfDescriptors; Index++) {
//         EFI_GCD_MEMORY_SPACE_DESCRIPTOR *Desc = &MemorySpaceMap[Index];
//         Print(L"BaseAddress: 0x%lx, Length: 0x%lx, Attributes: 0x%lx\n",
//             Desc->BaseAddress, Desc->Length, Desc->Attributes);
//     }

//     // Free allocated memory (if allocated dynamically)
//     FreePool(MemorySpaceMap);
// }

VOID EFIAPI fuzz_interrupt_handler(
  IN CONST  EFI_EXCEPTION_TYPE  InterruptType,
  IN CONST  EFI_SYSTEM_CONTEXT  SystemContext
  )
{
    LIBAFL_QEMU_END(LIBAFL_QEMU_END_CRASH);  // return crash
}

VOID PrintSmmReport(
  SMM_MODULES_HANDLER_PROTOCOL_INFO *Report
  )
{
    Print(L"SMRAM: %p %p %x %x\n",Report->CpuStart, Report->PhysicalStart, Report->PhysicalSize,sizeof(SMM_MODULES_HANDLER_PROTOCOL_INFO));

    for(int i = 0 ; i < Report->NumModules; i++)
    {
      Print(L"smi module: %g %p %x\n",&Report->info[i].Guid,Report->info[i].ImageBase,Report->info[i].ImageSize);
      for(int j = 0; j < Report->info[i].NumSmiHandlers; j++)
      {
        Print(L"  smi handler: %g\n",&Report->info[i].SmiHandlers[j]);
      }
      for(int j = 0; j < Report->info[i].NumProduceProtocols; j++)
      {
        Print(L"  produce protocol: %g\n",&Report->info[i].ProduceProtocols[j]);
      }
      for(int j = 0; j < Report->info[i].NumConsumeProtocols; j++)
      {
        Print(L"  consume protocol: %g\n",&Report->info[i].ConsumeProtocols[j]);
      }
    }
    for(int i = 0 ; i < Report->NumNonLoadedModules; i++)
    {
      Print(L"nonloaded smi module: %g\n",&Report->NonLoadedModules[i]);
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
    Print(L"Error: Unable to locate gEdkiiPiSmmCommunicationRegionTableGuid. %r\n",Status);
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
  CommBuffer = (UINT8 *)(Entry->PhysicalStart);
  CommHeader = (EFI_SMM_COMMUNICATE_HEADER *)CommBuffer;
  CommData = (UINT8 *)CommHeader->Data;
  return Status;
}


EFI_STATUS SmmFuzzExceptionHandle()
{
  EFI_STATUS Status;
  EFI_CPU_ARCH_PROTOCOL *CpuProtocol = NULL;
  Status = gBS->LocateProtocol(&gEfiCpuArchProtocolGuid, NULL, (VOID **)&CpuProtocol);
  if (EFI_ERROR(Status)) {
      Print(L"Error: Unable to locate gEfiCpuArchProtocolGuid. %r\n",Status);
      return Status;
  }
  for(int i = 0 ; i < 20 ; i++)
    CpuProtocol->RegisterInterruptHandler(CpuProtocol, i, fuzz_interrupt_handler);
  return Status;
}

EFI_STATUS SmmCall(GUID *ID, UINTN size)
{
  UINTN CommSize;
  EFI_STATUS Status;
  CopyMem (&CommHeader->HeaderGuid, ID, sizeof(GUID));
  CommHeader->MessageLength = size;
  CommSize = size + sizeof(EFI_SMM_COMMUNICATE_HEADER);
  Status = SmmCommunication->Communicate(SmmCommunication,CommBuffer,&CommSize);
  if (EFI_ERROR (Status)) {
    Print(L"Error: SmmCommunication gEfiSmmReportSmmModuleInfoGuid error. %r\n",Status);
    return Status;
  }
  return Status;
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
UefiMain(
    IN EFI_HANDLE ImageHandle,
    IN EFI_SYSTEM_TABLE *SystemTable)
{
    
    EFI_STATUS Status;
    
    SMM_MODULES_HANDLER_PROTOCOL_INFO *ReportData;
    SMM_MODULES_HANDLER_PROTOCOL_INFO *ReportDataBackup;
    UINTN  MinimalSizeNeeded = sizeof(SMM_MODULES_HANDLER_PROTOCOL_INFO);

    // SmmFuzzExceptionHandle();

    
    Status = gBS->LocateProtocol(&gEfiSmmCommunicationProtocolGuid, NULL, (void **)&SmmCommunication);
    if (EFI_ERROR(Status)) {
        Print(L"Error: Unable to locate gEfiSmmCommunicationProtocolGuid. %r\n",Status);
        return Status;
    }
    Status = GetSmmCommBuffer(MinimalSizeNeeded);
    if (EFI_ERROR(Status)) {
        Print(L"Error: Unable to get smm comm buffer. %r\n",Status);
        return Status;
    }
    
    
    ReportData = (SMM_MODULES_HANDLER_PROTOCOL_INFO*)CommData;
    
    ReportDataBackup = AllocatePool(sizeof(SMM_MODULES_HANDLER_PROTOCOL_INFO));

    Status = SmmCall(&gEfiSmmReportSmmModuleInfoGuid, MinimalSizeNeeded);
    if (EFI_ERROR(Status)) {
        Print(L"Error: Unable to call gEfiSmmReportSmmModuleInfoGuid. %r\n",Status);
        return Status;
    }
    CopyMem (ReportDataBackup,ReportData,sizeof(SMM_MODULES_HANDLER_PROTOCOL_INFO));


    LIBAFL_QEMU_END(LIBAFL_QEMU_END_SMM_FUZZ_START);
    Print(L"value is\n"); // print  255(-1)


    LIBAFL_QEMU_END(LIBAFL_QEMU_END_SMM_FUZZ_END);

    // LIBAFL_QEMU_SMM_REPORT_NUM_STREAM(5);
    // LIBAFL_QEMU_END(LIBAFL_QEMU_END_SMM_FUZZ_START);
    // LIBAFL_QEMU_END(LIBAFL_QEMU_END_SMM_FUZZ_END);

    // for(int i = 0 ; i < ReportDataBackup->NumHandlers ; i++) 
    // {
    //   CopyMem (&CommHeader->HeaderGuid, &ReportDataBackup->Handlers[i], sizeof(ReportDataBackup->Handlers[i]));
    //   CommHeader->MessageLength = MinimalSizeNeeded;
    //   CommSize = MinimalSizeNeeded;
    //   LIBAFL_QEMU_SMM_INPUT_STREAM_VIRT(i + 1,(libafl_word)ReportData,(libafl_word)MinimalSizeNeeded);
    //   Status = SmmCommunication->Communicate(SmmCommunication,CommBuffer,&CommSize);
    //   if (EFI_ERROR (Status)) {
    //     Print(L"Error: SmmCommunication error. %r\n",Status);
    //     LIBAFL_QEMU_END(1);
    //   }
    // }


    
    return EFI_SUCCESS;
}