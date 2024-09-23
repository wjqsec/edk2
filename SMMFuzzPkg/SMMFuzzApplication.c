#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Protocol/SmmCommunication.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>

#include <Guid/MemoryProfile.h>
#include <Guid/PiSmmCommunicationRegionTable.h>
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
    EFI_SMM_COMMUNICATION_PROTOCOL *SmmCommunication;
    UINTN CommSize;
    UINT8 *CommBuffer;
    EFI_SMM_COMMUNICATE_HEADER *CommHeader;
    EFI_MEMORY_DESCRIPTOR  *Entry;
    UINTN  Index;
    UINTN  Size;
    EDKII_PI_SMM_COMMUNICATION_REGION_TABLE  *PiSmmCommunicationRegionTable;
    UINTN  MinimalSizeNeeded = 0x500;

    Status = gBS->LocateProtocol(&gEfiSmmCommunicationProtocolGuid, NULL, (void **)&SmmCommunication);
    if (EFI_ERROR(Status)) {
        Print(L"Error: Unable to locate SMM Communication Protocol. %r\n",Status);
        return Status;
    }


    Status = EfiGetSystemConfigurationTable (
             &gEdkiiPiSmmCommunicationRegionTableGuid,
             (VOID **)&PiSmmCommunicationRegionTable
             );
    if (EFI_ERROR (Status)) {
      Print(L"SmramProfile: Get PiSmmCommunicationRegionTable - %r\n", Status);
      return Status;
    }
    ASSERT (PiSmmCommunicationRegionTable != NULL);

    Entry = (EFI_MEMORY_DESCRIPTOR *)(PiSmmCommunicationRegionTable + 1);
    Size  = 0;
    for (Index = 0; Index < PiSmmCommunicationRegionTable->NumberOfEntries; Index++) {
      if (Entry->Type == EfiConventionalMemory) {
        Size = EFI_PAGES_TO_SIZE ((UINTN)Entry->NumberOfPages);
        if (Size >= MinimalSizeNeeded) {
          break;
        }
      }

      Entry = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)Entry + PiSmmCommunicationRegionTable->DescriptorSize);
    }

    ASSERT (Index < PiSmmCommunicationRegionTable->NumberOfEntries);
    CommBuffer = (UINT8 *)(Entry->PhysicalStart);
    CommHeader = (EFI_SMM_COMMUNICATE_HEADER *)CommBuffer;

    CopyMem (&CommHeader->HeaderGuid, &gEfiDxeSmmReadyToLockProtocolGuid, sizeof (gEfiDxeSmmReadyToLockProtocolGuid));

    CommHeader->MessageLength = MinimalSizeNeeded;
    CommSize = MinimalSizeNeeded;
    Status = SmmCommunication->Communicate(SmmCommunication,CommBuffer,&CommSize);

    if (EFI_ERROR (Status)) {
      Print(L"SmramProfile: SmmCommunication %r\n",Status);
      return Status;
    }

    Print(L"OKOKOKOKOKOKOKOKOKOKO\n");
    return EFI_SUCCESS;
}