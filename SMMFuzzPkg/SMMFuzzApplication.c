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



#include "libafl_qemu.h"


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

// VOID EFIAPI fuzz_interrupt_handler(
//   IN CONST  EFI_EXCEPTION_TYPE  InterruptType,
//   IN CONST  EFI_SYSTEM_CONTEXT  SystemContext
//   )
// {
//     LIBAFL_QEMU_END(0);  // return crash
// }
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
    // EFI_CPU_ARCH_PROTOCOL *CpuProtocol = NULL;
    EFI_SMM_COMMUNICATION_PROTOCOL *SmmCommunication;
    UINTN CommSize;
    UINT8 *CommBuffer;
    EFI_SMM_COMMUNICATE_HEADER *CommHeader;
    EFI_MEMORY_DESCRIPTOR  *Entry;
    UINTN  Index;
    UINTN  Size;
    EDKII_PI_SMM_COMMUNICATION_REGION_TABLE  *PiSmmCommunicationRegionTable;
    SMM_MODULES_HANDLER_PROTOCOL_INFO *ReportData;
    SMM_MODULES_HANDLER_PROTOCOL_INFO *ReportDataBackup;
    UINTN  MinimalSizeNeeded = sizeof(SMM_MODULES_HANDLER_PROTOCOL_INFO);
    // Status = gBS->LocateProtocol(&gEfiCpuArchProtocolGuid, NULL, (VOID **)&CpuProtocol);
    // if (EFI_ERROR(Status)) {
    //     Print(L"Error: Unable to locate gEfiCpuArchProtocolGuid. %r\n",Status);
    //     return Status;
    // }
    // for(int i = 0 ; i < 20 ; i++)
    //   CpuProtocol->RegisterInterruptHandler(CpuProtocol, i, fuzz_interrupt_handler);

    Status = gBS->LocateProtocol(&gEfiSmmCommunicationProtocolGuid, NULL, (void **)&SmmCommunication);
    if (EFI_ERROR(Status)) {
        Print(L"Error: Unable to locate gEfiSmmCommunicationProtocolGuid. %r\n",Status);
        return Status;
    }

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
    
    ReportData = (SMM_MODULES_HANDLER_PROTOCOL_INFO*)(CommHeader->Data);
    
    ReportDataBackup = AllocatePool(sizeof(SMM_MODULES_HANDLER_PROTOCOL_INFO));

    
    // CopyMem (&CommHeader->HeaderGuid, &gEfiSmmLockBoxCommunicationGuid, sizeof(gEfiSmmLockBoxCommunicationGuid));
    // CommHeader->MessageLength = MinimalSizeNeeded;
    // CommSize = MinimalSizeNeeded;
    // Status = SmmCommunication->Communicate(SmmCommunication,CommBuffer,NULL);

    // if (EFI_ERROR (Status)) {
    //   Print(L"Error: SmmCommunication gEfiSmmLockBoxCommunicationGuid error. %r\n",Status);
    //   return Status;
    // }


    CopyMem (&CommHeader->HeaderGuid, &gEfiSmmReportSmmModuleInfoGuid, sizeof(gEfiSmmReportSmmModuleInfoGuid));
    CommHeader->MessageLength = MinimalSizeNeeded;
    CommSize = MinimalSizeNeeded;
    Status = SmmCommunication->Communicate(SmmCommunication,CommBuffer,&CommSize);

    if (EFI_ERROR (Status)) {
      Print(L"Error: SmmCommunication gEfiSmmReportSmmModuleInfoGuid error. %r\n",Status);
      return Status;
    }
    CopyMem (ReportDataBackup,ReportData,sizeof(SMM_MODULES_HANDLER_PROTOCOL_INFO));

    Print(L"smram: %p %p %x\n",ReportDataBackup->CpuStart, ReportDataBackup->PhysicalStart, ReportDataBackup->PhysicalSize);

    for(int i = 0 ; i < ReportDataBackup->NumModules; i++)
    {
      Print(L"smi module: %g %p %x\n",&ReportDataBackup->info[i].Guid,ReportDataBackup->info[i].ImageBase,ReportDataBackup->info[i].ImageSize);
      for(int j = 0; j < ReportDataBackup->info[i].NumSmiHandlers; j++)
      {
        Print(L"smi handler: %g\n",&ReportDataBackup->info[i].SmiHandlers[j]);
      }
      for(int j = 0; j < ReportDataBackup->info[i].NumProduceProtocols; j++)
      {
        Print(L"produce protocol: %g\n",&ReportDataBackup->info[i].ProduceProtocols[j]);
      }
      for(int j = 0; j < ReportDataBackup->info[i].NumConsumeProtocols; j++)
      {
        Print(L"consume protocol: %g\n",&ReportDataBackup->info[i].ConsumeProtocols[j]);
      }
    }
    Print(L"OKOKOKOKOKOKOKOKOKOK\n");
    while(1)
    {
      ;
    }

    // LIBAFL_QEMU_SMM_REPORT_NUM_STREAM(ReportDataBackup->NumHandlers);
    // LIBAFL_QEMU_LOAD();
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


    // LIBAFL_QEMU_END(1);
    return EFI_SUCCESS;
}