/** @file
  System Management System Table Services SmmInstallConfigurationTable service

  Copyright (c) 2009 - 2018, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "PiSmmCore.h"
#include <Uefi/UefiSpec.h>
#define CONFIG_TABLE_SIZE_INCREASED  0x10

UINTN  mSmmSystemTableAllocateSize = 0;

/**
  The SmmInstallConfigurationTable() function is used to maintain the list
  of configuration tables that are stored in the System Management System
  Table.  The list is stored as an array of (GUID, Pointer) pairs.  The list
  must be allocated from pool memory with PoolType set to EfiRuntimeServicesData.

  @param  SystemTable      A pointer to the SMM System Table (SMST).
  @param  Guid             A pointer to the GUID for the entry to add, update, or remove.
  @param  Table            A pointer to the buffer of the table to add.
  @param  TableSize        The size of the table to install.

  @retval EFI_SUCCESS           The (Guid, Table) pair was added, updated, or removed.
  @retval EFI_INVALID_PARAMETER Guid is not valid.
  @retval EFI_NOT_FOUND         An attempt was made to delete a non-existent entry.
  @retval EFI_OUT_OF_RESOURCES  There is not enough memory available to complete the operation.

**/
EFI_STATUS
EFIAPI
SmmInstallConfigurationTable (
  IN  CONST EFI_SMM_SYSTEM_TABLE2  *SystemTable,
  IN  CONST EFI_GUID               *Guid,
  IN  VOID                         *Table,
  IN  UINTN                        TableSize
  )
{
  UINTN                    Index;
  EFI_CONFIGURATION_TABLE  *ConfigurationTable;
  EFI_CONFIGURATION_TABLE  *OldTable;

  //
  // If Guid is NULL, then this operation cannot be performed
  //
  if (Guid == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  ConfigurationTable = gSmmCorePrivate->Smst->SmmConfigurationTable;

  //
  // Search all the table for an entry that matches Guid
  //
  for (Index = 0; Index < gSmmCorePrivate->Smst->NumberOfTableEntries; Index++) {
    if (CompareGuid (Guid, &(ConfigurationTable[Index].VendorGuid))) {
      break;
    }
  }

  if (Index < gSmmCorePrivate->Smst->NumberOfTableEntries) {
    //
    // A match was found, so this is either a modify or a delete operation
    //
    if (Table != NULL) {
      //
      // If Table is not NULL, then this is a modify operation.
      // Modify the table entry and return.
      //
      ConfigurationTable[Index].VendorTable = Table;
      return EFI_SUCCESS;
    }

    //
    // A match was found and Table is NULL, so this is a delete operation.
    //
    gSmmCorePrivate->Smst->NumberOfTableEntries--;

    //
    // Copy over deleted entry
    //
    CopyMem (
      &(ConfigurationTable[Index]),
      &(ConfigurationTable[Index + 1]),
      (gSmmCorePrivate->Smst->NumberOfTableEntries - Index) * sizeof (EFI_CONFIGURATION_TABLE)
      );
  } else {
    //
    // No matching GUIDs were found, so this is an add operation.
    //
    if (Table == NULL) {
      //
      // If Table is NULL on an add operation, then return an error.
      //
      return EFI_NOT_FOUND;
    }

    //
    // Assume that Index == gSmmCorePrivate->Smst->NumberOfTableEntries
    //
    if ((Index * sizeof (EFI_CONFIGURATION_TABLE)) >= mSmmSystemTableAllocateSize) {
      //
      // Allocate a table with one additional entry.
      //
      mSmmSystemTableAllocateSize += (CONFIG_TABLE_SIZE_INCREASED * sizeof (EFI_CONFIGURATION_TABLE));
      ConfigurationTable           = AllocatePool (mSmmSystemTableAllocateSize);
      if (ConfigurationTable == NULL) {
        //
        // If a new table could not be allocated, then return an error.
        //
        return EFI_OUT_OF_RESOURCES;
      }

      if (gSmmCorePrivate->Smst->SmmConfigurationTable != NULL) {
        //
        // Copy the old table to the new table.
        //
        CopyMem (
          ConfigurationTable,
          gSmmCorePrivate->Smst->SmmConfigurationTable,
          Index * sizeof (EFI_CONFIGURATION_TABLE)
          );

        //
        // Record the old table pointer.
        //
        OldTable = gSmmCorePrivate->Smst->SmmConfigurationTable;

        //
        // As the SmmInstallConfigurationTable() may be re-entered by FreePool() in
        // its calling stack, updating System table to the new table pointer must
        // be done before calling FreePool() to free the old table.
        // It can make sure the gSmmCorePrivate->Smst->SmmConfigurationTable point to the new
        // table and avoid the errors of use-after-free to the old table by the
        // reenter of SmmInstallConfigurationTable() in FreePool()'s calling stack.
        //
        gSmmCorePrivate->Smst->SmmConfigurationTable = ConfigurationTable;

        //
        // Free the old table after updating System Table to the new table pointer.
        //
        FreePool (OldTable);
      } else {
        //
        // Update System Table
        //
        gSmmCorePrivate->Smst->SmmConfigurationTable = ConfigurationTable;
      }
    }

    //
    // Fill in the new entry
    //
    CopyGuid ((VOID *)&ConfigurationTable[Index].VendorGuid, Guid);
    ConfigurationTable[Index].VendorTable = Table;

    //
    // This is an add operation, so increment the number of table entries
    //
    gSmmCorePrivate->Smst->NumberOfTableEntries++;
  }

  //
  // CRC-32 field is ignorable for SMM System Table and should be set to zero
  //

  return EFI_SUCCESS;
}
EFI_STATUS
EFIAPI
DummyRuntimeSmm(VOID)
{
  DEBUG((DEBUG_INFO,"DummyRuntimeSmm Ok\n"));
  return EFI_SUCCESS;
}
EFI_STATUS
EFIAPI EFI_GET_VARIABLE_FUZZ(
  IN     CHAR16                      *VariableName,
  IN     EFI_GUID                    *VendorGuid,
  OUT    UINT32                      *Attributes     OPTIONAL,
  IN OUT UINTN                       *DataSize,
  OUT    VOID                        *Data           OPTIONAL
) {
  LIBAFL_QEMU_SMM_GET_VARIABLE_FUZZ_DATA((UINTN)Data, (UINTN)*DataSize);
  DEBUG((DEBUG_INFO,"get RuntimeServiceGetVariable SMM Fuzz data"));
  if (StrCmp(VariableName, L"NvramMailBox") == 0) {
    DEBUG((DEBUG_INFO,"Fuzzing NvramMailBox\n"));
    UINT64 *DataPtr = (UINT64 *)Data;
    DataPtr[1] = (UINT64)DummyRuntimeSmm;
  } 
  return EFI_SUCCESS;
}
EFI_RUNTIME_SERVICES *RuntimeServicePtr = NULL;
EFI_STATUS
EFIAPI
SmmInstallConfigurationTableFuzz (
  IN  CONST EFI_SMM_SYSTEM_TABLE2  *SystemTable,
  IN  CONST EFI_GUID               *Guid,
  IN  VOID                         *Table,
  IN  UINTN                        TableSize
  )
{
  GUID RuntimeSMMGuid = { 0x395c33fe, 0x287f, 0x413e, { 0xa0, 0x55, 0x80, 0x88, 0xc0, 0xe1, 0xd4, 0x3e } };
  if (CompareGuid(Guid, &RuntimeSMMGuid))
  {
    RuntimeServicePtr = (EFI_RUNTIME_SERVICES *)Table;
    RuntimeServicePtr->GetTime = (EFI_GET_TIME)DummyRuntimeSmm;
    RuntimeServicePtr->SetTime = (EFI_SET_TIME)DummyRuntimeSmm;
    RuntimeServicePtr->GetWakeupTime = (EFI_GET_WAKEUP_TIME)DummyRuntimeSmm;
    RuntimeServicePtr->SetWakeupTime = (EFI_SET_WAKEUP_TIME)DummyRuntimeSmm;
    RuntimeServicePtr->SetVirtualAddressMap = (EFI_SET_VIRTUAL_ADDRESS_MAP)DummyRuntimeSmm;
    RuntimeServicePtr->ConvertPointer = (EFI_CONVERT_POINTER)DummyRuntimeSmm;
    RuntimeServicePtr->GetVariable = (EFI_GET_VARIABLE)EFI_GET_VARIABLE_FUZZ;
    RuntimeServicePtr->GetNextVariableName = (EFI_GET_NEXT_VARIABLE_NAME)DummyRuntimeSmm;
    RuntimeServicePtr->SetVariable = (EFI_SET_VARIABLE)DummyRuntimeSmm;
    RuntimeServicePtr->GetNextHighMonotonicCount = (EFI_GET_NEXT_HIGH_MONO_COUNT)DummyRuntimeSmm;
    RuntimeServicePtr->ResetSystem = (EFI_RESET_SYSTEM)DummyRuntimeSmm;
    RuntimeServicePtr->UpdateCapsule = (EFI_UPDATE_CAPSULE)DummyRuntimeSmm;
    RuntimeServicePtr->QueryCapsuleCapabilities = (EFI_QUERY_CAPSULE_CAPABILITIES)DummyRuntimeSmm;
    RuntimeServicePtr->QueryVariableInfo = (EFI_QUERY_VARIABLE_INFO)DummyRuntimeSmm;
  }
  DEBUG((DEBUG_INFO,"SmmInstallConfigurationTable %g\n",Guid));
  EFI_STATUS Status = SmmInstallConfigurationTable(SystemTable, Guid, Table, TableSize);
  return Status;
}