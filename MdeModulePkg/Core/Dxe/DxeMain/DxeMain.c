/** @file
  DXE Core Main Entry Point

Copyright (c) 2006 - 2022, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "DxeMain.h"
#include "libafl_qemu.h"

SMM_FUZZ_GLOBAL_DATA SmmFuzzGlobalData;
//
// DXE Core Global Variables for Protocols from PEI
//
EFI_HANDLE  mDecompressHandle = NULL;

//
// DXE Core globals for Architecture Protocols
//
EFI_SECURITY_ARCH_PROTOCOL        *gSecurity      = NULL;
EFI_SECURITY2_ARCH_PROTOCOL       *gSecurity2     = NULL;
EFI_CPU_ARCH_PROTOCOL             *gCpu           = NULL;
EFI_METRONOME_ARCH_PROTOCOL       *gMetronome     = NULL;
EFI_TIMER_ARCH_PROTOCOL           *gTimer         = NULL;
EFI_BDS_ARCH_PROTOCOL             *gBds           = NULL;
EFI_WATCHDOG_TIMER_ARCH_PROTOCOL  *gWatchdogTimer = NULL;

//
// DXE Core globals for optional protocol dependencies
//
EFI_SMM_BASE2_PROTOCOL  *gSmmBase2 = NULL;

//
// DXE Core Global used to update core loaded image protocol handle
//
EFI_GUID                   *gDxeCoreFileName;
EFI_LOADED_IMAGE_PROTOCOL  *gDxeCoreLoadedImage;

//
// DXE Core Module Variables
//
EFI_BOOT_SERVICES  mBootServices = {
  {
    EFI_BOOT_SERVICES_SIGNATURE,                                                          // Signature
    EFI_BOOT_SERVICES_REVISION,                                                           // Revision
    sizeof (EFI_BOOT_SERVICES),                                                           // HeaderSize
    0,                                                                                    // CRC32
    0                                                                                     // Reserved
  },
  (EFI_RAISE_TPL)CoreRaiseTpl,                                                            // RaiseTPL
  (EFI_RESTORE_TPL)CoreRestoreTpl,                                                        // RestoreTPL
  (EFI_ALLOCATE_PAGES)CoreAllocatePages,                                                  // AllocatePages
  (EFI_FREE_PAGES)CoreFreePages,                                                          // FreePages
  (EFI_GET_MEMORY_MAP)CoreGetMemoryMap,                                                   // GetMemoryMap
  (EFI_ALLOCATE_POOL)CoreAllocatePool,                                                    // AllocatePool
  (EFI_FREE_POOL)CoreFreePool,                                                            // FreePool
  (EFI_CREATE_EVENT)CoreCreateEvent,                                                      // CreateEvent
  (EFI_SET_TIMER)CoreSetTimer,                                                            // SetTimer
  (EFI_WAIT_FOR_EVENT)CoreWaitForEvent,                                                   // WaitForEvent
  (EFI_SIGNAL_EVENT)CoreSignalEvent,                                                      // SignalEvent
  (EFI_CLOSE_EVENT)CoreCloseEvent,                                                        // CloseEvent
  (EFI_CHECK_EVENT)CoreCheckEvent,                                                        // CheckEvent
  (EFI_INSTALL_PROTOCOL_INTERFACE)CoreInstallProtocolInterface,                           // InstallProtocolInterface
  (EFI_REINSTALL_PROTOCOL_INTERFACE)CoreReinstallProtocolInterface,                       // ReinstallProtocolInterface
  (EFI_UNINSTALL_PROTOCOL_INTERFACE)CoreUninstallProtocolInterface,                       // UninstallProtocolInterface
  (EFI_HANDLE_PROTOCOL)CoreHandleProtocol,                                                // HandleProtocol
  (VOID *)NULL,                                                                           // Reserved
  (EFI_REGISTER_PROTOCOL_NOTIFY)CoreRegisterProtocolNotify,                               // RegisterProtocolNotify
  (EFI_LOCATE_HANDLE)CoreLocateHandle,                                                    // LocateHandle
  (EFI_LOCATE_DEVICE_PATH)CoreLocateDevicePath,                                           // LocateDevicePath
  (EFI_INSTALL_CONFIGURATION_TABLE)CoreInstallConfigurationTable,                         // InstallConfigurationTable
  (EFI_IMAGE_LOAD)CoreLoadImage,                                                          // LoadImage
  (EFI_IMAGE_START)CoreStartImage,                                                        // StartImage
  (EFI_EXIT)CoreExit,                                                                     // Exit
  (EFI_IMAGE_UNLOAD)CoreUnloadImage,                                                      // UnloadImage
  (EFI_EXIT_BOOT_SERVICES)CoreExitBootServices,                                           // ExitBootServices
  (EFI_GET_NEXT_MONOTONIC_COUNT)CoreEfiNotAvailableYetArg1,                               // GetNextMonotonicCount
  (EFI_STALL)CoreStall,                                                                   // Stall
  (EFI_SET_WATCHDOG_TIMER)CoreSetWatchdogTimer,                                           // SetWatchdogTimer
  (EFI_CONNECT_CONTROLLER)CoreConnectController,                                          // ConnectController
  (EFI_DISCONNECT_CONTROLLER)CoreDisconnectController,                                    // DisconnectController
  (EFI_OPEN_PROTOCOL)CoreOpenProtocol,                                                    // OpenProtocol
  (EFI_CLOSE_PROTOCOL)CoreCloseProtocol,                                                  // CloseProtocol
  (EFI_OPEN_PROTOCOL_INFORMATION)CoreOpenProtocolInformation,                             // OpenProtocolInformation
  (EFI_PROTOCOLS_PER_HANDLE)CoreProtocolsPerHandle,                                       // ProtocolsPerHandle
  (EFI_LOCATE_HANDLE_BUFFER)CoreLocateHandleBuffer,                                       // LocateHandleBuffer
  (EFI_LOCATE_PROTOCOL)CoreLocateProtocol,                                                // LocateProtocol
  (EFI_INSTALL_MULTIPLE_PROTOCOL_INTERFACES)CoreInstallMultipleProtocolInterfaces,        // InstallMultipleProtocolInterfaces
  (EFI_UNINSTALL_MULTIPLE_PROTOCOL_INTERFACES)CoreUninstallMultipleProtocolInterfaces,    // UninstallMultipleProtocolInterfaces
  (EFI_CALCULATE_CRC32)CoreEfiNotAvailableYetArg3,                                        // CalculateCrc32
  (EFI_COPY_MEM)CopyMem,                                                                  // CopyMem
  (EFI_SET_MEM)SetMem,                                                                    // SetMem
  (EFI_CREATE_EVENT_EX)CoreCreateEventEx                                                  // CreateEventEx
};

EFI_DXE_SERVICES  mDxeServices = {
  {
    DXE_SERVICES_SIGNATURE,                                           // Signature
    DXE_SERVICES_REVISION,                                            // Revision
    sizeof (DXE_SERVICES),                                            // HeaderSize
    0,                                                                // CRC32
    0                                                                 // Reserved
  },
  (EFI_ADD_MEMORY_SPACE)CoreAddMemorySpace,                               // AddMemorySpace
  (EFI_ALLOCATE_MEMORY_SPACE)CoreAllocateMemorySpace,                     // AllocateMemorySpace
  (EFI_FREE_MEMORY_SPACE)CoreFreeMemorySpace,                             // FreeMemorySpace
  (EFI_REMOVE_MEMORY_SPACE)CoreRemoveMemorySpace,                         // RemoveMemorySpace
  (EFI_GET_MEMORY_SPACE_DESCRIPTOR)CoreGetMemorySpaceDescriptor,          // GetMemorySpaceDescriptor
  (EFI_SET_MEMORY_SPACE_ATTRIBUTES)CoreSetMemorySpaceAttributes,          // SetMemorySpaceAttributes
  (EFI_GET_MEMORY_SPACE_MAP)CoreGetMemorySpaceMap,                        // GetMemorySpaceMap
  (EFI_ADD_IO_SPACE)CoreAddIoSpace,                                       // AddIoSpace
  (EFI_ALLOCATE_IO_SPACE)CoreAllocateIoSpace,                             // AllocateIoSpace
  (EFI_FREE_IO_SPACE)CoreFreeIoSpace,                                     // FreeIoSpace
  (EFI_REMOVE_IO_SPACE)CoreRemoveIoSpace,                                 // RemoveIoSpace
  (EFI_GET_IO_SPACE_DESCRIPTOR)CoreGetIoSpaceDescriptor,                  // GetIoSpaceDescriptor
  (EFI_GET_IO_SPACE_MAP)CoreGetIoSpaceMap,                                // GetIoSpaceMap
  (EFI_DISPATCH)CoreDispatcher,                                           // Dispatch
  (EFI_SCHEDULE)CoreSchedule,                                             // Schedule
  (EFI_TRUST)CoreTrust,                                                   // Trust
  (EFI_PROCESS_FIRMWARE_VOLUME)CoreProcessFirmwareVolume,                 // ProcessFirmwareVolume
  (EFI_SET_MEMORY_SPACE_CAPABILITIES)CoreSetMemorySpaceCapabilities,      // SetMemorySpaceCapabilities
};

EFI_SYSTEM_TABLE  mEfiSystemTableTemplate = {
  {
    EFI_SYSTEM_TABLE_SIGNATURE,                                           // Signature
    EFI_SYSTEM_TABLE_REVISION,                                            // Revision
    sizeof (EFI_SYSTEM_TABLE),                                            // HeaderSize
    0,                                                                    // CRC32
    0                                                                     // Reserved
  },
  NULL,                                                                   // FirmwareVendor
  0,                                                                      // FirmwareRevision
  NULL,                                                                   // ConsoleInHandle
  NULL,                                                                   // ConIn
  NULL,                                                                   // ConsoleOutHandle
  NULL,                                                                   // ConOut
  NULL,                                                                   // StandardErrorHandle
  NULL,                                                                   // StdErr
  NULL,                                                                   // RuntimeServices
  &mBootServices,                                                         // BootServices
  0,                                                                      // NumberOfConfigurationTableEntries
  NULL                                                                    // ConfigurationTable
};

EFI_RUNTIME_SERVICES  mEfiRuntimeServicesTableTemplate = {
  {
    EFI_RUNTIME_SERVICES_SIGNATURE,                               // Signature
    EFI_RUNTIME_SERVICES_REVISION,                                // Revision
    sizeof (EFI_RUNTIME_SERVICES),                                // HeaderSize
    0,                                                            // CRC32
    0                                                             // Reserved
  },
  (EFI_GET_TIME)CoreEfiNotAvailableYetArg2,                       // GetTime
  (EFI_SET_TIME)CoreEfiNotAvailableYetArg1,                       // SetTime
  (EFI_GET_WAKEUP_TIME)CoreEfiNotAvailableYetArg3,                // GetWakeupTime
  (EFI_SET_WAKEUP_TIME)CoreEfiNotAvailableYetArg2,                // SetWakeupTime
  (EFI_SET_VIRTUAL_ADDRESS_MAP)CoreEfiNotAvailableYetArg4,        // SetVirtualAddressMap
  (EFI_CONVERT_POINTER)CoreEfiNotAvailableYetArg2,                // ConvertPointer
  (EFI_GET_VARIABLE)CoreEfiNotAvailableYetArg5,                   // GetVariable
  (EFI_GET_NEXT_VARIABLE_NAME)CoreEfiNotAvailableYetArg3,         // GetNextVariableName
  (EFI_SET_VARIABLE)CoreEfiNotAvailableYetArg5,                   // SetVariable
  (EFI_GET_NEXT_HIGH_MONO_COUNT)CoreEfiNotAvailableYetArg1,       // GetNextHighMonotonicCount
  (EFI_RESET_SYSTEM)CoreEfiNotAvailableYetArg4,                   // ResetSystem
  (EFI_UPDATE_CAPSULE)CoreEfiNotAvailableYetArg3,                 // UpdateCapsule
  (EFI_QUERY_CAPSULE_CAPABILITIES)CoreEfiNotAvailableYetArg4,     // QueryCapsuleCapabilities
  (EFI_QUERY_VARIABLE_INFO)CoreEfiNotAvailableYetArg4             // QueryVariableInfo
};

EFI_RUNTIME_ARCH_PROTOCOL  gRuntimeTemplate = {
  INITIALIZE_LIST_HEAD_VARIABLE (gRuntimeTemplate.ImageHead),
  INITIALIZE_LIST_HEAD_VARIABLE (gRuntimeTemplate.EventHead),

  //
  // Make sure Size != sizeof (EFI_MEMORY_DESCRIPTOR). This will
  // prevent people from having pointer math bugs in their code.
  // now you have to use *DescriptorSize to make things work.
  //
  sizeof (EFI_MEMORY_DESCRIPTOR) + sizeof (UINT64) - (sizeof (EFI_MEMORY_DESCRIPTOR) % sizeof (UINT64)),
  EFI_MEMORY_DESCRIPTOR_VERSION,
  0,
  NULL,
  NULL,
  FALSE,
  FALSE
};

EFI_RUNTIME_ARCH_PROTOCOL  *gRuntime = &gRuntimeTemplate;

//
// DXE Core Global Variables for the EFI System Table, Boot Services Table,
// DXE Services Table, and Runtime Services Table
//
EFI_DXE_SERVICES  *gDxeCoreDS = &mDxeServices;
EFI_SYSTEM_TABLE  *gDxeCoreST = NULL;

//
// For debug initialize gDxeCoreRT to template. gDxeCoreRT must be allocated from RT memory
//  but gDxeCoreRT is used for ASSERT () and DEBUG () type macros so lets give it
//  a value that will not cause debug infrastructure to crash early on.
//
EFI_RUNTIME_SERVICES  *gDxeCoreRT         = &mEfiRuntimeServicesTableTemplate;
EFI_HANDLE            gDxeCoreImageHandle = NULL;

BOOLEAN  gMemoryMapTerminated = FALSE;

//
// EFI Decompress Protocol
//
EFI_DECOMPRESS_PROTOCOL  gEfiDecompress = {
  DxeMainUefiDecompressGetInfo,
  DxeMainUefiDecompress
};

//
// For Loading modules at fixed address feature, the configuration table is to cache the top address below which to load
// Runtime code&boot time code
//
GLOBAL_REMOVE_IF_UNREFERENCED EFI_LOAD_FIXED_ADDRESS_CONFIGURATION_TABLE  gLoadModuleAtFixAddressConfigurationTable = { 0, 0 };

// Main entry point to the DXE Core
//

/**
  Main entry point to DXE Core.

  @param  HobStart               Pointer to the beginning of the HOB List from PEI.

  @return This function should never return.

**/
VOID
EFIAPI
DxeMain (
  IN  VOID  *HobStart
  )
{
  EFI_STATUS                    Status;
  EFI_PHYSICAL_ADDRESS          MemoryBaseAddress;
  UINT64                        MemoryLength;
  PE_COFF_LOADER_IMAGE_CONTEXT  ImageContext;
  UINTN                         Index;
  EFI_HOB_GUID_TYPE             *GuidHob;
  EFI_VECTOR_HANDOFF_INFO       *VectorInfoList;
  EFI_VECTOR_HANDOFF_INFO       *VectorInfo;
  VOID                          *EntryPoint;
  
  //
  // Setup the default exception handlers
  //
  VectorInfoList = NULL;
  GuidHob        = GetNextGuidHob (&gEfiVectorHandoffInfoPpiGuid, HobStart);
  if (GuidHob != NULL) {
    VectorInfoList = (EFI_VECTOR_HANDOFF_INFO *)(GET_GUID_HOB_DATA (GuidHob));
  }

  Status = InitializeCpuExceptionHandlers (VectorInfoList);
  ASSERT_EFI_ERROR (Status);

  //
  // Setup Stack Guard
  //
  if (PcdGetBool (PcdCpuStackGuard)) {
    Status = InitializeSeparateExceptionStacks (NULL, NULL);
    ASSERT_EFI_ERROR (Status);
  }

  //
  // Initialize Debug Agent to support source level debug in DXE phase
  //
  InitializeDebugAgent (DEBUG_AGENT_INIT_DXE_CORE, HobStart, NULL);

  //
  // Initialize Memory Services
  //
  CoreInitializeMemoryServices (&HobStart, &MemoryBaseAddress, &MemoryLength);

  MemoryProfileInit (HobStart);

  //
  // Start the Handle Services.
  //
  Status = CoreInitializeHandleServices ();
  ASSERT_EFI_ERROR (Status);

  //
  // Start the Image Services.
  //
  Status = CoreInitializeImageServices (HobStart);
  ASSERT_EFI_ERROR (Status);

  //
  // Initialize the Global Coherency Domain Services
  //
  Status = CoreInitializeGcdServices (&HobStart, MemoryBaseAddress, MemoryLength);
  ASSERT_EFI_ERROR (Status);

  //
  // Allocate the EFI System Table and EFI Runtime Service Table from EfiRuntimeServicesData
  // Use the templates to initialize the contents of the EFI System Table and EFI Runtime Services Table
  //
  gDxeCoreST = AllocateRuntimeCopyPool (sizeof (EFI_SYSTEM_TABLE), &mEfiSystemTableTemplate);
  ASSERT (gDxeCoreST != NULL);

  gDxeCoreRT = AllocateRuntimeCopyPool (sizeof (EFI_RUNTIME_SERVICES), &mEfiRuntimeServicesTableTemplate);
  ASSERT (gDxeCoreRT != NULL);

  gDxeCoreST->RuntimeServices = gDxeCoreRT;

  //
  // Update DXE Core Loaded Image Protocol with allocated UEFI System Table
  //
  gDxeCoreLoadedImage->SystemTable = gDxeCoreST;

  //
  // Call constructor for all libraries
  //
  ProcessLibraryConstructorList (gDxeCoreImageHandle, gDxeCoreST);
  PERF_CROSSMODULE_END ("PEI");
  PERF_CROSSMODULE_BEGIN ("DXE");

  //
  // Log MemoryBaseAddress and MemoryLength again (from
  // CoreInitializeMemoryServices()), now that library constructors have
  // executed.
  //
  DEBUG ((
    DEBUG_INFO,
    "%a: MemoryBaseAddress=0x%Lx MemoryLength=0x%Lx\n",
    __func__,
    MemoryBaseAddress,
    MemoryLength
    ));

  //
  // Report DXE Core image information to the PE/COFF Extra Action Library
  //
  ZeroMem (&ImageContext, sizeof (ImageContext));
  ImageContext.ImageAddress  = (EFI_PHYSICAL_ADDRESS)(UINTN)gDxeCoreLoadedImage->ImageBase;
  ImageContext.PdbPointer    = PeCoffLoaderGetPdbPointer ((VOID *)(UINTN)ImageContext.ImageAddress);
  ImageContext.SizeOfHeaders = PeCoffGetSizeOfHeaders ((VOID *)(UINTN)ImageContext.ImageAddress);
  Status                     = PeCoffLoaderGetEntryPoint ((VOID *)(UINTN)ImageContext.ImageAddress, &EntryPoint);
  if (Status == EFI_SUCCESS) {
    ImageContext.EntryPoint = (EFI_PHYSICAL_ADDRESS)(UINTN)EntryPoint;
  }

  ImageContext.Handle    = (VOID *)(UINTN)gDxeCoreLoadedImage->ImageBase;
  ImageContext.ImageRead = PeCoffLoaderImageReadFromMemory;
  PeCoffLoaderRelocateImageExtraAction (&ImageContext);

  //
  // Install the DXE Services Table into the EFI System Tables's Configuration Table
  //
  Status = CoreInstallConfigurationTable (&gEfiDxeServicesTableGuid, gDxeCoreDS);
  ASSERT_EFI_ERROR (Status);

  //
  // Install the HOB List into the EFI System Tables's Configuration Table
  //
  Status = CoreInstallConfigurationTable (&gEfiHobListGuid, HobStart);
  ASSERT_EFI_ERROR (Status);

  //
  // Install Memory Type Information Table into the EFI System Tables's Configuration Table
  //
  Status = CoreInstallConfigurationTable (&gEfiMemoryTypeInformationGuid, &gMemoryTypeInformation);
  ASSERT_EFI_ERROR (Status);

  //
  // If Loading modules At fixed address feature is enabled, install Load moduels at fixed address
  // Configuration Table so that user could easily to retrieve the top address to load Dxe and PEI
  // Code and Tseg base to load SMM driver.
  //
  if (PcdGet64 (PcdLoadModuleAtFixAddressEnable) != 0) {
    Status = CoreInstallConfigurationTable (&gLoadFixedAddressConfigurationTableGuid, &gLoadModuleAtFixAddressConfigurationTable);
    ASSERT_EFI_ERROR (Status);
  }

  //
  // Report Status Code here for DXE_ENTRY_POINT once it is available
  //
  REPORT_STATUS_CODE (
    EFI_PROGRESS_CODE,
    (EFI_SOFTWARE_DXE_CORE | EFI_SW_DXE_CORE_PC_ENTRY_POINT)
    );

  //
  // Create the aligned system table pointer structure that is used by external
  // debuggers to locate the system table...  Also, install debug image info
  // configuration table.
  //
  CoreInitializeDebugImageInfoTable ();
  CoreNewDebugImageInfoEntry (
    EFI_DEBUG_IMAGE_INFO_TYPE_NORMAL,
    gDxeCoreLoadedImage,
    gDxeCoreImageHandle
    );

  DEBUG ((DEBUG_INFO | DEBUG_LOAD, "HOBLIST address in DXE = 0x%p\n", HobStart));

  DEBUG_CODE_BEGIN ();
  EFI_PEI_HOB_POINTERS  Hob;

  for (Hob.Raw = HobStart; !END_OF_HOB_LIST (Hob); Hob.Raw = GET_NEXT_HOB (Hob)) {
    if (GET_HOB_TYPE (Hob) == EFI_HOB_TYPE_MEMORY_ALLOCATION) {
      DEBUG ((
        DEBUG_INFO | DEBUG_LOAD,
        "Memory Allocation 0x%08x 0x%0lx - 0x%0lx\n", \
        Hob.MemoryAllocation->AllocDescriptor.MemoryType,                      \
        Hob.MemoryAllocation->AllocDescriptor.MemoryBaseAddress,               \
        Hob.MemoryAllocation->AllocDescriptor.MemoryBaseAddress + Hob.MemoryAllocation->AllocDescriptor.MemoryLength - 1
        ));
    }
  }

  for (Hob.Raw = HobStart; !END_OF_HOB_LIST (Hob); Hob.Raw = GET_NEXT_HOB (Hob)) {
    if (GET_HOB_TYPE (Hob) == EFI_HOB_TYPE_FV) {
      DEBUG ((
        DEBUG_INFO | DEBUG_LOAD,
        "FV Hob            0x%0lx - 0x%0lx\n",
        Hob.FirmwareVolume->BaseAddress,
        Hob.FirmwareVolume->BaseAddress + Hob.FirmwareVolume->Length - 1
        ));
    } else if (GET_HOB_TYPE (Hob) == EFI_HOB_TYPE_FV2) {
      DEBUG ((
        DEBUG_INFO | DEBUG_LOAD,
        "FV2 Hob           0x%0lx - 0x%0lx\n",
        Hob.FirmwareVolume2->BaseAddress,
        Hob.FirmwareVolume2->BaseAddress + Hob.FirmwareVolume2->Length - 1
        ));
      DEBUG ((
        DEBUG_INFO | DEBUG_LOAD,
        "                  %g - %g\n",
        &Hob.FirmwareVolume2->FvName,
        &Hob.FirmwareVolume2->FileName
        ));
    } else if (GET_HOB_TYPE (Hob) == EFI_HOB_TYPE_FV3) {
      DEBUG ((
        DEBUG_INFO | DEBUG_LOAD,
        "FV3 Hob           0x%0lx - 0x%0lx - 0x%x - 0x%x\n",
        Hob.FirmwareVolume3->BaseAddress,
        Hob.FirmwareVolume3->BaseAddress + Hob.FirmwareVolume3->Length - 1,
        Hob.FirmwareVolume3->AuthenticationStatus,
        Hob.FirmwareVolume3->ExtractedFv
        ));
      if (Hob.FirmwareVolume3->ExtractedFv) {
        DEBUG ((
          DEBUG_INFO | DEBUG_LOAD,
          "                  %g - %g\n",
          &Hob.FirmwareVolume3->FvName,
          &Hob.FirmwareVolume3->FileName
          ));
      }
    }
  }

  DEBUG_CODE_END ();

  //
  // Initialize the Event Services
  //
  Status = CoreInitializeEventServices ();
  ASSERT_EFI_ERROR (Status);

  MemoryProfileInstallProtocol ();

  CoreInitializeMemoryAttributesTable ();
  CoreInitializeMemoryProtection ();

  //
  // Get persisted vector hand-off info from GUIDeed HOB again due to HobStart may be updated,
  // and install configuration table
  //
  GuidHob = GetNextGuidHob (&gEfiVectorHandoffInfoPpiGuid, HobStart);
  if (GuidHob != NULL) {
    VectorInfoList = (EFI_VECTOR_HANDOFF_INFO *)(GET_GUID_HOB_DATA (GuidHob));
    VectorInfo     = VectorInfoList;
    Index          = 1;
    while (VectorInfo->Attribute != EFI_VECTOR_HANDOFF_LAST_ENTRY) {
      VectorInfo++;
      Index++;
    }

    VectorInfo = AllocateCopyPool (sizeof (EFI_VECTOR_HANDOFF_INFO) * Index, (VOID *)VectorInfoList);
    ASSERT (VectorInfo != NULL);
    Status = CoreInstallConfigurationTable (&gEfiVectorHandoffTableGuid, (VOID *)VectorInfo);
    ASSERT_EFI_ERROR (Status);
  }

  //
  // Get the Protocols that were passed in from PEI to DXE through GUIDed HOBs
  //
  // These Protocols are not architectural. This implementation is sharing code between
  // PEI and DXE in order to save FLASH space. These Protocols could also be implemented
  // as part of the DXE Core. However, that would also require the DXE Core to be ported
  // each time a different CPU is used, a different Decompression algorithm is used, or a
  // different Image type is used. By placing these Protocols in PEI, the DXE Core remains
  // generic, and only PEI and the Arch Protocols need to be ported from Platform to Platform,
  // and from CPU to CPU.
  //

  //
  // Publish the EFI, Tiano, and Custom Decompress protocols for use by other DXE components
  //
  Status = CoreInstallMultipleProtocolInterfaces (
             &mDecompressHandle,
             &gEfiDecompressProtocolGuid,
             &gEfiDecompress,
             NULL
             );
  ASSERT_EFI_ERROR (Status);

  //
  // Register for the GUIDs of the Architectural Protocols, so the rest of the
  // EFI Boot Services and EFI Runtime Services tables can be filled in.
  // Also register for the GUIDs of optional protocols.
  //
  CoreNotifyOnProtocolInstallation ();

  //
  // Produce Firmware Volume Protocols, one for each FV in the HOB list.
  //
  Status = FwVolBlockDriverInit (gDxeCoreImageHandle, gDxeCoreST);
  ASSERT_EFI_ERROR (Status);

  Status = FwVolDriverInit (gDxeCoreImageHandle, gDxeCoreST);
  ASSERT_EFI_ERROR (Status);

  //
  // Produce the Section Extraction Protocol
  //
  Status = InitializeSectionExtraction (gDxeCoreImageHandle, gDxeCoreST);
  ASSERT_EFI_ERROR (Status);

  // SMM FUZZ
  InstallSmmFuzzProtocol();
  HookGBS();
  //
  // Initialize the DXE Dispatcher
  //
  CoreInitializeDispatcher ();

  //
  // Invoke the DXE Dispatcher
  //
  CoreDispatcher ();
  //
  // Display Architectural protocols that were not loaded if this is DEBUG build
  //
  DEBUG_CODE_BEGIN ();
  CoreDisplayMissingArchProtocols ();
  DEBUG_CODE_END ();

  //
  // Display any drivers that were not dispatched because dependency expression
  // evaluated to false if this is a debug build
  //
  DEBUG_CODE_BEGIN ();
  CoreDisplayDiscoveredNotDispatched ();
  DEBUG_CODE_END ();

  //
  // Assert if the Architectural Protocols are not present.
  //
  Status = CoreAllEfiServicesAvailable ();
  if (EFI_ERROR (Status)) {
    //
    // Report Status code that some Architectural Protocols are not present.
    //
    REPORT_STATUS_CODE (
      EFI_ERROR_CODE | EFI_ERROR_MAJOR,
      (EFI_SOFTWARE_DXE_CORE | EFI_SW_DXE_CORE_EC_NO_ARCH)
      );
  }

  ASSERT_EFI_ERROR (Status);

  //
  // Report Status code before transfer control to BDS
  //
  REPORT_STATUS_CODE (
    EFI_PROGRESS_CODE,
    (EFI_SOFTWARE_DXE_CORE | EFI_SW_DXE_CORE_PC_HANDOFF_TO_NEXT)
    );

  //
  // Transfer control to the BDS Architectural Protocol
  //
  gBds->Entry (gBds);

  //
  // BDS should never return
  //
  ASSERT (FALSE);
  CpuDeadLoop ();

  UNREACHABLE ();
}

/**
  Place holder function until all the Boot Services and Runtime Services are
  available.

  @param  Arg1                   Undefined

  @return EFI_NOT_AVAILABLE_YET

**/
EFI_STATUS
EFIAPI
CoreEfiNotAvailableYetArg1 (
  UINTN  Arg1
  )
{
  //
  // This function should never be executed.  If it does, then the architectural protocols
  // have not been designed correctly.  The CpuBreakpoint () is commented out for now until the
  // DXE Core and all the Architectural Protocols are complete.
  //

  return EFI_NOT_AVAILABLE_YET;
}

/**
  Place holder function until all the Boot Services and Runtime Services are available.

  @param  Arg1                   Undefined
  @param  Arg2                   Undefined

  @return EFI_NOT_AVAILABLE_YET

**/
EFI_STATUS
EFIAPI
CoreEfiNotAvailableYetArg2 (
  UINTN  Arg1,
  UINTN  Arg2
  )
{
  //
  // This function should never be executed.  If it does, then the architectural protocols
  // have not been designed correctly.  The CpuBreakpoint () is commented out for now until the
  // DXE Core and all the Architectural Protocols are complete.
  //

  return EFI_NOT_AVAILABLE_YET;
}

/**
  Place holder function until all the Boot Services and Runtime Services are available.

  @param  Arg1                   Undefined
  @param  Arg2                   Undefined
  @param  Arg3                   Undefined

  @return EFI_NOT_AVAILABLE_YET

**/
EFI_STATUS
EFIAPI
CoreEfiNotAvailableYetArg3 (
  UINTN  Arg1,
  UINTN  Arg2,
  UINTN  Arg3
  )
{
  //
  // This function should never be executed.  If it does, then the architectural protocols
  // have not been designed correctly.  The CpuBreakpoint () is commented out for now until the
  // DXE Core and all the Architectural Protocols are complete.
  //

  return EFI_NOT_AVAILABLE_YET;
}

/**
  Place holder function until all the Boot Services and Runtime Services are available.

  @param  Arg1                   Undefined
  @param  Arg2                   Undefined
  @param  Arg3                   Undefined
  @param  Arg4                   Undefined

  @return EFI_NOT_AVAILABLE_YET

**/
EFI_STATUS
EFIAPI
CoreEfiNotAvailableYetArg4 (
  UINTN  Arg1,
  UINTN  Arg2,
  UINTN  Arg3,
  UINTN  Arg4
  )
{
  //
  // This function should never be executed.  If it does, then the architectural protocols
  // have not been designed correctly.  The CpuBreakpoint () is commented out for now until the
  // DXE Core and all the Architectural Protocols are complete.
  //

  return EFI_NOT_AVAILABLE_YET;
}

/**
  Place holder function until all the Boot Services and Runtime Services are available.

  @param  Arg1                   Undefined
  @param  Arg2                   Undefined
  @param  Arg3                   Undefined
  @param  Arg4                   Undefined
  @param  Arg5                   Undefined

  @return EFI_NOT_AVAILABLE_YET

**/
EFI_STATUS
EFIAPI
CoreEfiNotAvailableYetArg5 (
  UINTN  Arg1,
  UINTN  Arg2,
  UINTN  Arg3,
  UINTN  Arg4,
  UINTN  Arg5
  )
{
  //
  // This function should never be executed.  If it does, then the architectural protocols
  // have not been designed correctly.  The CpuBreakpoint () is commented out for now until the
  // DXE Core and all the Architectural Protocols are complete.
  //

  return EFI_NOT_AVAILABLE_YET;
}

/**
  Calcualte the 32-bit CRC in a EFI table using the service provided by the
  gRuntime service.

  @param  Hdr                    Pointer to an EFI standard header

**/
VOID
CalculateEfiHdrCrc (
  IN  OUT EFI_TABLE_HEADER  *Hdr
  )
{
  UINT32  Crc;

  Hdr->CRC32 = 0;

  //
  // If gBS->CalculateCrce32 () == CoreEfiNotAvailableYet () then
  //  Crc will come back as zero if we set it to zero here
  //
  Crc = 0;
  gBS->CalculateCrc32 ((UINT8 *)Hdr, Hdr->HeaderSize, &Crc);
  Hdr->CRC32 = Crc;
}

/**
  Terminates all boot services.

  @param  ImageHandle            Handle that identifies the exiting image.
  @param  MapKey                 Key to the latest memory map.

  @retval EFI_SUCCESS            Boot Services terminated
  @retval EFI_INVALID_PARAMETER  MapKey is incorrect.

**/
EFI_STATUS
EFIAPI
CoreExitBootServices (
  IN EFI_HANDLE  ImageHandle,
  IN UINTN       MapKey
  )
{
  EFI_STATUS  Status;

  //
  // Notify other drivers of their last chance to use boot services
  // before the memory map is terminated.
  //
  CoreNotifySignalList (&gEfiEventBeforeExitBootServicesGuid);

  //
  // Disable Timer
  //
  gTimer->SetTimerPeriod (gTimer, 0);

  //
  // Terminate memory services if the MapKey matches
  //
  Status = CoreTerminateMemoryMap (MapKey);
  if (EFI_ERROR (Status)) {
    //
    // Notify other drivers that ExitBootServices fail
    //
    CoreNotifySignalList (&gEventExitBootServicesFailedGuid);
    return Status;
  }

  gMemoryMapTerminated = TRUE;

  //
  // Notify other drivers that we are exiting boot services.
  //
  CoreNotifySignalList (&gEfiEventExitBootServicesGuid);

  //
  // Report that ExitBootServices() has been called
  //
  REPORT_STATUS_CODE (
    EFI_PROGRESS_CODE,
    (EFI_SOFTWARE_EFI_BOOT_SERVICE | EFI_SW_BS_PC_EXIT_BOOT_SERVICES)
    );

  MemoryProtectionExitBootServicesCallback ();

  //
  // Disable interrupt of Debug timer.
  //
  SaveAndSetDebugTimerInterrupt (FALSE);

  //
  // Disable CPU Interrupts
  //
  gCpu->DisableInterrupt (gCpu);

  //
  // Clear the non-runtime values of the EFI System Table
  //
  gDxeCoreST->BootServices        = NULL;
  gDxeCoreST->ConIn               = NULL;
  gDxeCoreST->ConsoleInHandle     = NULL;
  gDxeCoreST->ConOut              = NULL;
  gDxeCoreST->ConsoleOutHandle    = NULL;
  gDxeCoreST->StdErr              = NULL;
  gDxeCoreST->StandardErrorHandle = NULL;

  //
  // Recompute the 32-bit CRC of the EFI System Table
  //
  CalculateEfiHdrCrc (&gDxeCoreST->Hdr);

  //
  // Zero out the Boot Service Table
  //
  ZeroMem (gBS, sizeof (EFI_BOOT_SERVICES));
  gBS = NULL;

  //
  // Update the AtRuntime field in Runtiem AP.
  //
  gRuntime->AtRuntime = TRUE;

  return Status;
}

/**
  Given a compressed source buffer, this function retrieves the size of the
  uncompressed buffer and the size of the scratch buffer required to decompress
  the compressed source buffer.

  The GetInfo() function retrieves the size of the uncompressed buffer and the
  temporary scratch buffer required to decompress the buffer specified by Source
  and SourceSize. If the size of the uncompressed buffer or the size of the
  scratch buffer cannot be determined from the compressed data specified by
  Source and SourceData, then EFI_INVALID_PARAMETER is returned. Otherwise, the
  size of the uncompressed buffer is returned in DestinationSize, the size of
  the scratch buffer is returned in ScratchSize, and EFI_SUCCESS is returned.
  The GetInfo() function does not have scratch buffer available to perform a
  thorough checking of the validity of the source data. It just retrieves the
  "Original Size" field from the beginning bytes of the source data and output
  it as DestinationSize. And ScratchSize is specific to the decompression
  implementation.

  @param  This               A pointer to the EFI_DECOMPRESS_PROTOCOL instance.
  @param  Source             The source buffer containing the compressed data.
  @param  SourceSize         The size, in bytes, of the source buffer.
  @param  DestinationSize    A pointer to the size, in bytes, of the
                             uncompressed buffer that will be generated when the
                             compressed buffer specified by Source and
                             SourceSize is decompressed.
  @param  ScratchSize        A pointer to the size, in bytes, of the scratch
                             buffer that is required to decompress the
                             compressed buffer specified by Source and
                             SourceSize.

  @retval EFI_SUCCESS        The size of the uncompressed data was returned in
                             DestinationSize and the size of the scratch buffer
                             was returned in ScratchSize.
  @retval EFI_INVALID_PARAMETER The size of the uncompressed data or the size of
                                the scratch buffer cannot be determined from the
                                compressed data specified by Source and
                                SourceSize.

**/
EFI_STATUS
EFIAPI
DxeMainUefiDecompressGetInfo (
  IN EFI_DECOMPRESS_PROTOCOL  *This,
  IN   VOID                   *Source,
  IN   UINT32                 SourceSize,
  OUT  UINT32                 *DestinationSize,
  OUT  UINT32                 *ScratchSize
  )
{
  if ((Source == NULL) || (DestinationSize == NULL) || (ScratchSize == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  return UefiDecompressGetInfo (Source, SourceSize, DestinationSize, ScratchSize);
}

/**
  Decompresses a compressed source buffer.

  The Decompress() function extracts decompressed data to its original form.
  This protocol is designed so that the decompression algorithm can be
  implemented without using any memory services. As a result, the Decompress()
  Function is not allowed to call AllocatePool() or AllocatePages() in its
  implementation. It is the caller's responsibility to allocate and free the
  Destination and Scratch buffers.
  If the compressed source data specified by Source and SourceSize is
  successfully decompressed into Destination, then EFI_SUCCESS is returned. If
  the compressed source data specified by Source and SourceSize is not in a
  valid compressed data format, then EFI_INVALID_PARAMETER is returned.

  @param  This                A pointer to the EFI_DECOMPRESS_PROTOCOL instance.
  @param  Source              The source buffer containing the compressed data.
  @param  SourceSize          SourceSizeThe size of source data.
  @param  Destination         On output, the destination buffer that contains
                              the uncompressed data.
  @param  DestinationSize     The size of the destination buffer.  The size of
                              the destination buffer needed is obtained from
                              EFI_DECOMPRESS_PROTOCOL.GetInfo().
  @param  Scratch             A temporary scratch buffer that is used to perform
                              the decompression.
  @param  ScratchSize         The size of scratch buffer. The size of the
                              scratch buffer needed is obtained from GetInfo().

  @retval EFI_SUCCESS         Decompression completed successfully, and the
                              uncompressed buffer is returned in Destination.
  @retval EFI_INVALID_PARAMETER  The source buffer specified by Source and
                                 SourceSize is corrupted (not in a valid
                                 compressed format).

**/
EFI_STATUS
EFIAPI
DxeMainUefiDecompress (
  IN     EFI_DECOMPRESS_PROTOCOL  *This,
  IN     VOID                     *Source,
  IN     UINT32                   SourceSize,
  IN OUT VOID                     *Destination,
  IN     UINT32                   DestinationSize,
  IN OUT VOID                     *Scratch,
  IN     UINT32                   ScratchSize
  )
{
  EFI_STATUS  Status;
  UINT32      TestDestinationSize;
  UINT32      TestScratchSize;

  if ((Source == NULL) || (Destination == NULL) || (Scratch == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  Status = UefiDecompressGetInfo (Source, SourceSize, &TestDestinationSize, &TestScratchSize);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if ((ScratchSize < TestScratchSize) || (DestinationSize < TestDestinationSize)) {
    return RETURN_INVALID_PARAMETER;
  }

  return UefiDecompress (Source, Destination, Scratch);
}

EFI_RAISE_TPL EFI_RAISE_TPL_Old;
EFI_TPL EFIAPI EFI_RAISE_TPL_FUZZ(
  IN EFI_TPL NewTpl
) {
  EFI_TPL Ret;
  UINT64 OldInFuzz = SmmFuzzGlobalData.in_fuzz;
  SmmFuzzGlobalData.in_fuzz = 0; 
  Ret = EFI_RAISE_TPL_Old(NewTpl);
  SmmFuzzGlobalData.in_fuzz = OldInFuzz;
  return Ret;
}
EFI_RESTORE_TPL EFI_RESTORE_TPL_Old;
VOID
EFIAPI EFI_RESTORE_TPL_FUZZ(
  IN EFI_TPL      OldTpl
) {
  UINT64 OldInFuzz = SmmFuzzGlobalData.in_fuzz;
  SmmFuzzGlobalData.in_fuzz = 0; 
  EFI_RESTORE_TPL_Old(OldTpl);
  SmmFuzzGlobalData.in_fuzz = OldInFuzz;
}

// Memory Services
EFI_ALLOCATE_PAGES EFI_ALLOCATE_PAGES_Old;
EFI_STATUS EFIAPI EFI_ALLOCATE_PAGES_FUZZ(
  IN     EFI_ALLOCATE_TYPE            Type,
  IN     EFI_MEMORY_TYPE              MemoryType,
  IN     UINTN                        Pages,
  IN OUT EFI_PHYSICAL_ADDRESS         *Memory
) {
  EFI_STATUS Status;
  UINT64 OldInFuzz = SmmFuzzGlobalData.in_fuzz;
  SmmFuzzGlobalData.in_fuzz = 0; 
  Status = EFI_ALLOCATE_PAGES_Old(Type, MemoryType, Pages, Memory);
  SmmFuzzGlobalData.in_fuzz = OldInFuzz;
  DEBUG((DEBUG_INFO,"AllocatePages: %d %r\n",Pages, Status));
  return Status;
}

EFI_FREE_PAGES EFI_FREE_PAGES_Old;
EFI_STATUS EFIAPI EFI_FREE_PAGES_FUZZ(
  IN  EFI_PHYSICAL_ADDRESS         Memory,
  IN  UINTN                        Pages
) {
  EFI_STATUS Status;
  UINT64 OldInFuzz = SmmFuzzGlobalData.in_fuzz;
  SmmFuzzGlobalData.in_fuzz = 0; 
  Status = EFI_FREE_PAGES_Old(Memory, Pages);
  SmmFuzzGlobalData.in_fuzz = OldInFuzz;
  return Status;
}

EFI_GET_MEMORY_MAP EFI_GET_MEMORY_MAP_Old;
EFI_STATUS EFIAPI EFI_GET_MEMORY_MAP_FUZZ(
  IN OUT UINTN                       *MemoryMapSize,
  OUT    EFI_MEMORY_DESCRIPTOR       *MemoryMap,
  OUT    UINTN                       *MapKey,
  OUT    UINTN                       *DescriptorSize,
  OUT    UINT32                      *DescriptorVersion
) {
  EFI_STATUS Status;
  UINT64 OldInFuzz = SmmFuzzGlobalData.in_fuzz;
  SmmFuzzGlobalData.in_fuzz = 0; 
  Status = EFI_GET_MEMORY_MAP_Old(MemoryMapSize, MemoryMap, MapKey, DescriptorSize, DescriptorVersion);
  SmmFuzzGlobalData.in_fuzz = OldInFuzz;
  return Status;
}

EFI_ALLOCATE_POOL EFI_ALLOCATE_POOL_Old;
EFI_STATUS EFIAPI EFI_ALLOCATE_POOL_FUZZ(
  IN  EFI_MEMORY_TYPE              PoolType,
  IN  UINTN                        Size,
  OUT VOID                         **Buffer
) {
  EFI_STATUS Status;
  UINT64 OldInFuzz = SmmFuzzGlobalData.in_fuzz;
  SmmFuzzGlobalData.in_fuzz = 0; 
  Status = EFI_ALLOCATE_POOL_Old(PoolType, Size, Buffer);
  SmmFuzzGlobalData.in_fuzz = OldInFuzz;
  return Status;
}

EFI_FREE_POOL EFI_FREE_POOL_Old;
EFI_STATUS EFIAPI EFI_FREE_POOL_FUZZ(
  IN  VOID                         *Buffer
) {
  DEBUG((DEBUG_INFO,"EFI_FREE_POOL_FUZZ\n"));
  EFI_STATUS Status;
  UINT64 OldInFuzz = SmmFuzzGlobalData.in_fuzz;
  SmmFuzzGlobalData.in_fuzz = 0; 
  Status = EFI_FREE_POOL_Old(Buffer);
  SmmFuzzGlobalData.in_fuzz = OldInFuzz;
  DEBUG((DEBUG_INFO,"EFI_FREE_POOL_FUZZ %r\n",Status));
  return Status;
}

// Event & Timer Services
EFI_CREATE_EVENT EFI_CREATE_EVENT_Old;
EFI_STATUS EFIAPI EFI_CREATE_EVENT_FUZZ(
  IN  UINT32                       Type,
  IN  EFI_TPL                      NotifyTpl,
  IN  EFI_EVENT_NOTIFY             NotifyFunction OPTIONAL,
  IN  VOID                         *NotifyContext OPTIONAL,
  OUT EFI_EVENT                    *Event
) {
  
  EFI_STATUS Status;
  UINT64 OldInFuzz = SmmFuzzGlobalData.in_fuzz;
  SmmFuzzGlobalData.in_fuzz = 0; 
  if (OldInFuzz == 1)
    Status = EFI_SUCCESS;
  else
    Status = EFI_CREATE_EVENT_Old(Type, NotifyTpl, NotifyFunction, NotifyContext, Event);
  SmmFuzzGlobalData.in_fuzz = OldInFuzz;
  return Status;
}

EFI_SET_TIMER EFI_SET_TIMER_Old;
EFI_STATUS EFIAPI EFI_SET_TIMER_FUZZ(
  IN  EFI_EVENT                Event,
  IN  EFI_TIMER_DELAY          Type,
  IN  UINT64                   TriggerTime
) {
  EFI_STATUS Status;
  UINT64 OldInFuzz = SmmFuzzGlobalData.in_fuzz;
  SmmFuzzGlobalData.in_fuzz = 0; 
  Status = EFI_SET_TIMER_Old(Event, Type, TriggerTime);
  SmmFuzzGlobalData.in_fuzz = OldInFuzz;
  return Status;
}

EFI_WAIT_FOR_EVENT EFI_WAIT_FOR_EVENT_Old;
EFI_STATUS EFIAPI EFI_WAIT_FOR_EVENT_FUZZ(
  IN  UINTN                    NumberOfEvents,
  IN  EFI_EVENT                *Event,
  OUT UINTN                    *Index
) {
  EFI_STATUS Status;
  UINT64 OldInFuzz = SmmFuzzGlobalData.in_fuzz;
  SmmFuzzGlobalData.in_fuzz = 0; 
  Status = EFI_WAIT_FOR_EVENT_Old(NumberOfEvents, Event, Index);
  SmmFuzzGlobalData.in_fuzz = OldInFuzz;
  return Status;
}

EFI_SIGNAL_EVENT EFI_SIGNAL_EVENT_Old;
EFI_STATUS EFIAPI EFI_SIGNAL_EVENT_FUZZ(
  IN  EFI_EVENT                Event
) {
  EFI_STATUS Status;
  UINT64 OldInFuzz = SmmFuzzGlobalData.in_fuzz;
  SmmFuzzGlobalData.in_fuzz = 0; 
  Status = EFI_SIGNAL_EVENT_Old(Event);
  SmmFuzzGlobalData.in_fuzz = OldInFuzz;
  return Status;
}

EFI_CLOSE_EVENT EFI_CLOSE_EVENT_Old;
EFI_STATUS EFIAPI EFI_CLOSE_EVENT_FUZZ(
  IN EFI_EVENT                Event
) {
  EFI_STATUS Status;
  UINT64 OldInFuzz = SmmFuzzGlobalData.in_fuzz;
  SmmFuzzGlobalData.in_fuzz = 0; 
  Status = EFI_CLOSE_EVENT_Old(Event);
  SmmFuzzGlobalData.in_fuzz = OldInFuzz;
  return Status;
}

EFI_CHECK_EVENT EFI_CHECK_EVENT_Old;
EFI_STATUS EFIAPI EFI_CHECK_EVENT_FUZZ(
  IN EFI_EVENT                Event
) {
  EFI_STATUS Status;
  UINT64 OldInFuzz = SmmFuzzGlobalData.in_fuzz;
  SmmFuzzGlobalData.in_fuzz = 0; 
  Status = EFI_CHECK_EVENT_Old(Event);
  SmmFuzzGlobalData.in_fuzz = OldInFuzz;
  return Status;
}

// Protocol Handler Services
EFI_INSTALL_PROTOCOL_INTERFACE EFI_INSTALL_PROTOCOL_INTERFACE_Old;
EFI_STATUS EFIAPI EFI_INSTALL_PROTOCOL_INTERFACE_FUZZ(
  IN OUT EFI_HANDLE               *Handle,
  IN     EFI_GUID                 *Protocol,
  IN     EFI_INTERFACE_TYPE       InterfaceType,
  IN     VOID                     *Interface
) {
  EFI_STATUS Status;
  UINT64 OldInFuzz = SmmFuzzGlobalData.in_fuzz;
  if (OldInFuzz && CompareGuid(Protocol, &gEfiDriverBindingProtocolGuid))
    return EFI_SUCCESS;
  if (OldInFuzz) {
    VOID *T;
    if (CoreLocateProtocol(Protocol, NULL, &T) == EFI_SUCCESS)
      LIBAFL_QEMU_SMM_REPORT_CONFLICT_DXE_PROTOCOL((UINTN)Protocol);
  }
  SmmFuzzGlobalData.in_fuzz = 0; 
  Status = EFI_INSTALL_PROTOCOL_INTERFACE_Old(Handle, Protocol, InterfaceType, Interface);
  SmmFuzzGlobalData.in_fuzz = OldInFuzz;
  return Status;
}

EFI_REINSTALL_PROTOCOL_INTERFACE EFI_REINSTALL_PROTOCOL_INTERFACE_Old;
EFI_STATUS EFIAPI EFI_REINSTALL_PROTOCOL_INTERFACE_FUZZ(
  IN EFI_HANDLE               Handle,
  IN EFI_GUID                 *Protocol,
  IN VOID                     *OldInterface,
  IN VOID                     *NewInterface
) {
  EFI_STATUS Status;
  UINT64 OldInFuzz = SmmFuzzGlobalData.in_fuzz;
  SmmFuzzGlobalData.in_fuzz = 0; 
  Status = EFI_REINSTALL_PROTOCOL_INTERFACE_Old(Handle, Protocol, OldInterface, NewInterface);
  SmmFuzzGlobalData.in_fuzz = OldInFuzz;
  return Status;
}

EFI_UNINSTALL_PROTOCOL_INTERFACE EFI_UNINSTALL_PROTOCOL_INTERFACE_Old;
EFI_STATUS EFIAPI EFI_UNINSTALL_PROTOCOL_INTERFACE_FUZZ(
  IN EFI_HANDLE               Handle,
  IN EFI_GUID                 *Protocol,
  IN VOID                     *Interface
) {
  EFI_STATUS Status;
  UINT64 OldInFuzz = SmmFuzzGlobalData.in_fuzz;
  SmmFuzzGlobalData.in_fuzz = 0; 
  Status = EFI_UNINSTALL_PROTOCOL_INTERFACE_Old(Handle, Protocol, Interface);
  SmmFuzzGlobalData.in_fuzz = OldInFuzz;
  return Status;
}

EFI_HANDLE_PROTOCOL EFI_HANDLE_PROTOCOL_Old;
EFI_STATUS EFIAPI EFI_HANDLE_PROTOCOL_FUZZ(
  IN EFI_HANDLE               Handle,
  IN EFI_GUID                 *Protocol,
  OUT VOID                    **Interface
) {
  EFI_STATUS Status;
  UINT64 OldInFuzz = SmmFuzzGlobalData.in_fuzz;
  SmmFuzzGlobalData.in_fuzz = 0; 
  Status = EFI_HANDLE_PROTOCOL_Old(Handle, Protocol, Interface);
  SmmFuzzGlobalData.in_fuzz = OldInFuzz;
  return Status;
}
EFI_REGISTER_PROTOCOL_NOTIFY EFI_REGISTER_PROTOCOL_NOTIFY_Old;
EFI_STATUS EFIAPI EFI_REGISTER_PROTOCOL_NOTIFY_FUZZ(
  IN EFI_GUID                 *Protocol,
  IN EFI_EVENT                Event,
  OUT VOID                    **Registration
) {
  EFI_STATUS Status;
  UINT64 OldInFuzz = SmmFuzzGlobalData.in_fuzz;
  SmmFuzzGlobalData.in_fuzz = 0;
  Status = EFI_REGISTER_PROTOCOL_NOTIFY_Old(Protocol, Event, Registration);
  SmmFuzzGlobalData.in_fuzz = OldInFuzz;
  return Status;
}

EFI_LOCATE_HANDLE EFI_LOCATE_HANDLE_Old;
EFI_STATUS EFIAPI EFI_LOCATE_HANDLE_FUZZ(
  IN  EFI_LOCATE_SEARCH_TYPE     SearchType,
  IN  EFI_GUID                   *Protocol OPTIONAL,
  IN  VOID                       *SearchKey OPTIONAL,
  IN OUT UINTN                   *BufferSize,
  OUT EFI_HANDLE                 *Buffer
) {
  
  EFI_STATUS Status;
  UINT64 OldInFuzz = SmmFuzzGlobalData.in_fuzz;
  SmmFuzzGlobalData.in_fuzz = 0; 
  Status = EFI_LOCATE_HANDLE_Old(SearchType, Protocol, SearchKey, BufferSize, Buffer);
  SmmFuzzGlobalData.in_fuzz = OldInFuzz;
  return Status;
}

EFI_LOCATE_DEVICE_PATH EFI_LOCATE_DEVICE_PATH_Old;
EFI_STATUS EFIAPI EFI_LOCATE_DEVICE_PATH_FUZZ(
  IN     EFI_GUID                         *Protocol,
  IN OUT EFI_DEVICE_PATH_PROTOCOL         **DevicePath,
  OUT    EFI_HANDLE                       *Device
) {
  EFI_STATUS Status;
  UINT64 OldInFuzz = SmmFuzzGlobalData.in_fuzz;
  SmmFuzzGlobalData.in_fuzz = 0; 
  Status = EFI_LOCATE_DEVICE_PATH_Old(Protocol, DevicePath, Device);
  SmmFuzzGlobalData.in_fuzz = OldInFuzz;
  return Status;
}

EFI_INSTALL_CONFIGURATION_TABLE EFI_INSTALL_CONFIGURATION_TABLE_Old;
EFI_STATUS EFIAPI EFI_INSTALL_CONFIGURATION_TABLE_FUZZ(
  IN EFI_GUID                 *TableGuid,
  IN VOID                     *Table
) {
  EFI_STATUS Status;
  UINT64 OldInFuzz = SmmFuzzGlobalData.in_fuzz;
  SmmFuzzGlobalData.in_fuzz = 0; 
  Status = EFI_INSTALL_CONFIGURATION_TABLE_Old(TableGuid, Table);
  SmmFuzzGlobalData.in_fuzz = OldInFuzz;
  return Status;
}
EFI_IMAGE_LOAD EFI_IMAGE_LOAD_Old;
EFI_STATUS
EFIAPI EFI_IMAGE_LOAD_FUZZ(
  IN  BOOLEAN                      BootPolicy,
  IN  EFI_HANDLE                   ParentImageHandle,
  IN  EFI_DEVICE_PATH_PROTOCOL     *DevicePath   OPTIONAL,
  IN  VOID                         *SourceBuffer OPTIONAL,
  IN  UINTN                        SourceSize,
  OUT EFI_HANDLE                   *ImageHandle
) {
  EFI_STATUS Status;
  UINT64 OldInFuzz = SmmFuzzGlobalData.in_fuzz;
  SmmFuzzGlobalData.in_fuzz = 0; 
  Status = EFI_IMAGE_LOAD_Old(BootPolicy, ParentImageHandle, DevicePath, SourceBuffer, SourceSize, ImageHandle);
  SmmFuzzGlobalData.in_fuzz = OldInFuzz;
  return Status;
}

EFI_IMAGE_START EFI_IMAGE_START_Old;
EFI_STATUS EFIAPI EFI_IMAGE_START_FUZZ(
  IN EFI_HANDLE                  ImageHandle,
  IN OUT UINTN                   *ExitDataSize,
  OUT CHAR16                     **ExitData
) {
  EFI_STATUS Status;
  UINT64 OldInFuzz = SmmFuzzGlobalData.in_fuzz;
  SmmFuzzGlobalData.in_fuzz = 0; 
  Status = EFI_IMAGE_START_Old(ImageHandle, ExitDataSize, ExitData);
  SmmFuzzGlobalData.in_fuzz = OldInFuzz;
  return Status;
}

EFI_EXIT EFI_EXIT_Old;
EFI_STATUS EFIAPI EFI_EXIT_FUZZ(
  IN EFI_HANDLE   ImageHandle,
  IN EFI_STATUS   ExitStatus,
  IN UINTN        ExitDataSize,
  IN CHAR16       *ExitData
) {
  EFI_STATUS Status;
  UINT64 OldInFuzz = SmmFuzzGlobalData.in_fuzz;
  SmmFuzzGlobalData.in_fuzz = 0; 
  Status = EFI_EXIT_Old(ImageHandle, ExitStatus, ExitDataSize, ExitData);
  SmmFuzzGlobalData.in_fuzz = OldInFuzz;
  return Status;
}

EFI_IMAGE_UNLOAD EFI_IMAGE_UNLOAD_Old;
EFI_STATUS EFIAPI EFI_IMAGE_UNLOAD_FUZZ(
  IN EFI_HANDLE  ImageHandle
) {
  EFI_STATUS Status;
  UINT64 OldInFuzz = SmmFuzzGlobalData.in_fuzz;
  SmmFuzzGlobalData.in_fuzz = 0; 
  Status = EFI_IMAGE_UNLOAD_Old(ImageHandle);
  SmmFuzzGlobalData.in_fuzz = OldInFuzz;
  return Status;
}

EFI_EXIT_BOOT_SERVICES EFI_EXIT_BOOT_SERVICES_Old;
EFI_STATUS EFIAPI EFI_EXIT_BOOT_SERVICES_FUZZ(
  IN EFI_HANDLE   ImageHandle,
  IN UINTN        MapKey
) {
  EFI_STATUS Status;
  UINT64 OldInFuzz = SmmFuzzGlobalData.in_fuzz;
  SmmFuzzGlobalData.in_fuzz = 0; 
  Status = EFI_EXIT_BOOT_SERVICES_Old(ImageHandle, MapKey);
  SmmFuzzGlobalData.in_fuzz = OldInFuzz;
  return Status;
}

// Miscellaneous Services
EFI_GET_NEXT_MONOTONIC_COUNT EFI_GET_NEXT_MONOTONIC_COUNT_Old;
EFI_STATUS EFIAPI EFI_GET_NEXT_MONOTONIC_COUNT_FUZZ(
  OUT UINT64 *Count
) {
  EFI_STATUS Status;
  UINT64 OldInFuzz = SmmFuzzGlobalData.in_fuzz;
  SmmFuzzGlobalData.in_fuzz = 0; 
  Status = EFI_GET_NEXT_MONOTONIC_COUNT_Old(Count);
  SmmFuzzGlobalData.in_fuzz = OldInFuzz;
  return Status;
}

EFI_STALL EFI_STALL_Old;
EFI_STATUS EFIAPI EFI_STALL_FUZZ(
  IN UINTN   Microseconds
) {
  EFI_STATUS Status;
  UINT64 OldInFuzz = SmmFuzzGlobalData.in_fuzz;
  SmmFuzzGlobalData.in_fuzz = 0; 
  Status = EFI_STALL_Old(Microseconds);
  SmmFuzzGlobalData.in_fuzz = OldInFuzz;
  return Status;
}

EFI_SET_WATCHDOG_TIMER EFI_SET_WATCHDOG_TIMER_Old;
EFI_STATUS EFIAPI EFI_SET_WATCHDOG_TIMER_FUZZ(
  IN UINTN                    Timeout,
  IN UINT64                   WatchdogCode,
  IN UINTN                    DataSize,
  IN CHAR16                   *WatchdogData OPTIONAL
) {
  EFI_STATUS Status;
  UINT64 OldInFuzz = SmmFuzzGlobalData.in_fuzz;
  SmmFuzzGlobalData.in_fuzz = 0; 
  Status = EFI_SET_WATCHDOG_TIMER_Old(Timeout, WatchdogCode, DataSize, WatchdogData);
  SmmFuzzGlobalData.in_fuzz = OldInFuzz;
  return Status;
}

// DriverSupport Services
EFI_CONNECT_CONTROLLER EFI_CONNECT_CONTROLLER_Old;
EFI_STATUS EFIAPI EFI_CONNECT_CONTROLLER_FUZZ(
  IN  EFI_HANDLE                    ControllerHandle,
  IN  EFI_HANDLE                    *DriverImageHandle    OPTIONAL,
  IN  EFI_DEVICE_PATH_PROTOCOL      *RemainingDevicePath  OPTIONAL,
  IN  BOOLEAN                       Recursive
) {
  EFI_STATUS Status;
  UINT64 OldInFuzz = SmmFuzzGlobalData.in_fuzz;
  SmmFuzzGlobalData.in_fuzz = 0; 
  Status = EFI_CONNECT_CONTROLLER_Old(ControllerHandle, DriverImageHandle, RemainingDevicePath, Recursive);
  SmmFuzzGlobalData.in_fuzz = OldInFuzz;
  return Status;
}

EFI_DISCONNECT_CONTROLLER EFI_DISCONNECT_CONTROLLER_Old;
EFI_STATUS EFIAPI EFI_DISCONNECT_CONTROLLER_FUZZ(
  IN  EFI_HANDLE                     ControllerHandle,
  IN  EFI_HANDLE                     DriverImageHandle  OPTIONAL,
  IN  EFI_HANDLE                     ChildHandle        OPTIONAL
) {
  EFI_STATUS Status;
  UINT64 OldInFuzz = SmmFuzzGlobalData.in_fuzz;
  SmmFuzzGlobalData.in_fuzz = 0; 
  Status = EFI_DISCONNECT_CONTROLLER_Old(ControllerHandle, DriverImageHandle, ChildHandle);
  SmmFuzzGlobalData.in_fuzz = OldInFuzz;
  return Status;
}

// Open and Close Protocol Services
EFI_OPEN_PROTOCOL EFI_OPEN_PROTOCOL_Old;
EFI_STATUS
EFIAPI EFI_OPEN_PROTOCOL_FUZZ(
  IN  EFI_HANDLE                Handle,
  IN  EFI_GUID                  *Protocol,
  OUT VOID                      **Interface  OPTIONAL,
  IN  EFI_HANDLE                AgentHandle,
  IN  EFI_HANDLE                ControllerHandle,
  IN  UINT32                    Attributes
) {
  EFI_STATUS Status;
  UINT64 OldInFuzz = SmmFuzzGlobalData.in_fuzz;
  SmmFuzzGlobalData.in_fuzz = 0; 
  Status = EFI_OPEN_PROTOCOL_Old(Handle, Protocol, Interface, AgentHandle, ControllerHandle, Attributes);
  SmmFuzzGlobalData.in_fuzz = OldInFuzz;
  return Status;
}


EFI_CLOSE_PROTOCOL EFI_CLOSE_PROTOCOL_Old;
EFI_STATUS EFIAPI EFI_CLOSE_PROTOCOL_FUZZ(
  IN EFI_HANDLE               Handle,
  IN EFI_GUID                 *Protocol,
  IN EFI_HANDLE               AgentHandle,
  IN EFI_HANDLE               ControllerHandle
) {
  EFI_STATUS Status;
  UINT64 OldInFuzz = SmmFuzzGlobalData.in_fuzz;
  SmmFuzzGlobalData.in_fuzz = 0; 
  Status = EFI_CLOSE_PROTOCOL_Old(Handle, Protocol, AgentHandle, ControllerHandle);
  SmmFuzzGlobalData.in_fuzz = OldInFuzz;
  return Status;
}

EFI_OPEN_PROTOCOL_INFORMATION EFI_OPEN_PROTOCOL_INFORMATION_Old;
EFI_STATUS EFIAPI EFI_OPEN_PROTOCOL_INFORMATION_FUZZ(
  IN EFI_HANDLE               Handle,
  IN EFI_GUID                 *Protocol,
  OUT EFI_OPEN_PROTOCOL_INFORMATION_ENTRY **EntryBuffer,
  OUT UINTN                   *EntryCount
) {
  EFI_STATUS Status;
  UINT64 OldInFuzz = SmmFuzzGlobalData.in_fuzz;
  SmmFuzzGlobalData.in_fuzz = 0; 
  Status = EFI_OPEN_PROTOCOL_INFORMATION_Old(Handle, Protocol, EntryBuffer, EntryCount);
  SmmFuzzGlobalData.in_fuzz = OldInFuzz;
  return Status;
}

// Library Services
EFI_PROTOCOLS_PER_HANDLE EFI_PROTOCOLS_PER_HANDLE_Old;
EFI_STATUS EFIAPI EFI_PROTOCOLS_PER_HANDLE_FUZZ(
  IN  EFI_HANDLE      Handle,
  OUT EFI_GUID        ***ProtocolBuffer,
  OUT UINTN           *ProtocolBufferCount
) {
  EFI_STATUS Status;
  UINT64 OldInFuzz = SmmFuzzGlobalData.in_fuzz;
  SmmFuzzGlobalData.in_fuzz = 0; 
  Status = EFI_PROTOCOLS_PER_HANDLE_Old(Handle, ProtocolBuffer, ProtocolBufferCount);
  SmmFuzzGlobalData.in_fuzz = OldInFuzz;
  return Status;
}

EFI_LOCATE_HANDLE_BUFFER EFI_LOCATE_HANDLE_BUFFER_Old;
EFI_STATUS EFIAPI EFI_LOCATE_HANDLE_BUFFER_FUZZ(
  IN     EFI_LOCATE_SEARCH_TYPE       SearchType,
  IN     EFI_GUID                     *Protocol       OPTIONAL,
  IN     VOID                         *SearchKey      OPTIONAL,
  OUT    UINTN                        *NoHandles,
  OUT    EFI_HANDLE                   **Buffer
) {
  EFI_STATUS Status;
  UINT64 OldInFuzz = SmmFuzzGlobalData.in_fuzz;
  SmmFuzzGlobalData.in_fuzz = 0; 
  Status = EFI_LOCATE_HANDLE_BUFFER_Old(SearchType, Protocol, SearchKey, NoHandles, Buffer);
  SmmFuzzGlobalData.in_fuzz = OldInFuzz;
  return Status;
}

EFI_LOCATE_PROTOCOL EFI_LOCATE_PROTOCOL_Old;
EFI_STATUS EFIAPI EFI_LOCATE_PROTOCOL_FUZZ(
  IN  EFI_GUID                   *Protocol,
  IN  VOID                       *SearchKey OPTIONAL,
  OUT VOID                       **Interface
) {
  
  EFI_STATUS Status;
  UINT64 OldInFuzz = SmmFuzzGlobalData.in_fuzz;
  SmmFuzzGlobalData.in_fuzz = 0; 
  Status = EFI_LOCATE_PROTOCOL_Old(Protocol, SearchKey, Interface);
  SmmFuzzGlobalData.in_fuzz = OldInFuzz;
  DEBUG((DEBUG_INFO, "EFI_LOCATE_PROTOCOL_FUZZ %g %r %p\n",Protocol,Status,*Interface));
  return Status;
}

// 32-bit CRC Services
EFI_CALCULATE_CRC32 EFI_CALCULATE_CRC32_Old;
EFI_STATUS EFIAPI EFI_CALCULATE_CRC32_FUZZ(
  IN VOID        *Data,
  IN UINTN       DataLength,
  OUT UINT32     *Crc32
) {
  EFI_STATUS Status;
  UINT64 OldInFuzz = SmmFuzzGlobalData.in_fuzz;
  SmmFuzzGlobalData.in_fuzz = 0; 
  Status = EFI_CALCULATE_CRC32_Old(Data, DataLength, Crc32);
  SmmFuzzGlobalData.in_fuzz = OldInFuzz;
  return Status;
}

// Miscellaneous Services
EFI_COPY_MEM EFI_COPY_MEM_Old;
VOID EFIAPI EFI_COPY_MEM_FUZZ(
  OUT VOID   *Destination,
  IN  VOID   *Source,
  IN  UINTN  Length
) {
  UINT64 OldInFuzz = SmmFuzzGlobalData.in_fuzz;
  SmmFuzzGlobalData.in_fuzz = 0; 
  EFI_COPY_MEM_Old(Destination, Source, Length);
  SmmFuzzGlobalData.in_fuzz = OldInFuzz;
}

EFI_SET_MEM EFI_SET_MEM_Old;
VOID EFIAPI EFI_SET_MEM_FUZZ(
  OUT VOID   *Buffer,
  IN  UINTN  Length,
  IN  UINT8  Value
) {
  UINT64 OldInFuzz = SmmFuzzGlobalData.in_fuzz;
  SmmFuzzGlobalData.in_fuzz = 0; 
  EFI_SET_MEM_Old(Buffer, Length, Value);
  SmmFuzzGlobalData.in_fuzz = OldInFuzz;
}

EFI_CREATE_EVENT_EX EFI_CREATE_EVENT_EX_Old;
EFI_STATUS
EFIAPI EFI_CREATE_EVENT_EX_FUZZ(
  IN       UINT32                 Type,
  IN       EFI_TPL                NotifyTpl,
  IN       EFI_EVENT_NOTIFY       NotifyFunction OPTIONAL,
  IN CONST VOID                   *NotifyContext OPTIONAL,
  IN CONST EFI_GUID               *EventGroup    OPTIONAL,
  OUT      EFI_EVENT              *Event
) {
  EFI_STATUS Status;
  UINT64 OldInFuzz = SmmFuzzGlobalData.in_fuzz;
  SmmFuzzGlobalData.in_fuzz = 0; 
  Status = EFI_CREATE_EVENT_EX_Old(Type, NotifyTpl, NotifyFunction, NotifyContext, EventGroup, Event);
  SmmFuzzGlobalData.in_fuzz = OldInFuzz;
  return Status;
}

typedef struct _VENDOR_VARIABLE {
  UINT32 Attributes;
  CHAR16 *VariableName;
  EFI_GUID VendorGuid;
  VOID *Data;
  UINTN DataSize;
}VENDOR_VARIABLE;

EFI_GET_VARIABLE                  GetVariableOld;
EFI_STATUS
EFIAPI EFI_GET_VARIABLE_FUZZ(
  IN     CHAR16                      *VariableName,
  IN     EFI_GUID                    *VendorGuid,
  OUT    UINT32                      *Attributes     OPTIONAL,
  IN OUT UINTN                       *DataSize,
  OUT    VOID                        *Data           OPTIONAL
  )
{
  DEBUG((DEBUG_INFO, "EFI_GET_VARIABLE_FUZZ\n"));
  UINT64 OldInFuzz = SmmFuzzGlobalData.in_fuzz;
  if (OldInFuzz == 0)
    return GetVariableOld(VariableName, VendorGuid, Attributes, DataSize, Data);
  LIBAFL_QEMU_SMM_GET_VARIABLE_FUZZ_DATA((UINTN)Data, (UINTN)*DataSize);
  return EFI_SUCCESS;
}
EFI_SET_VARIABLE SetVariableOld;
EFI_STATUS
EFIAPI EFI_SET_VARIABLE_FUZZ(
  IN  CHAR16                       *VariableName,
  IN  EFI_GUID                     *VendorGuid,
  IN  UINT32                       Attributes,
  IN  UINTN                        DataSize,
  IN  VOID                         *Data
  )
{
  DEBUG((DEBUG_INFO, "EFI_SET_VARIABLE_FUZZ\n"));
  UINT64 OldInFuzz = SmmFuzzGlobalData.in_fuzz;
  if (OldInFuzz == 0)
    return SetVariableOld(VariableName, VendorGuid, Attributes, DataSize, Data);
  return EFI_SUCCESS;
}
VOID HookGBS (VOID) {
    // Task Priority Services
    EFI_RAISE_TPL_Old = gBS->RaiseTPL;
    gBS->RaiseTPL = EFI_RAISE_TPL_FUZZ;

    EFI_RESTORE_TPL_Old = gBS->RestoreTPL;
    gBS->RestoreTPL = EFI_RESTORE_TPL_FUZZ;

    // Memory Services
    EFI_ALLOCATE_PAGES_Old = gBS->AllocatePages;
    gBS->AllocatePages = EFI_ALLOCATE_PAGES_FUZZ;

    EFI_FREE_PAGES_Old = gBS->FreePages;
    gBS->FreePages = EFI_FREE_PAGES_FUZZ;

    EFI_GET_MEMORY_MAP_Old = gBS->GetMemoryMap;
    gBS->GetMemoryMap = EFI_GET_MEMORY_MAP_FUZZ;

    EFI_ALLOCATE_POOL_Old = gBS->AllocatePool;
    gBS->AllocatePool = EFI_ALLOCATE_POOL_FUZZ;

    EFI_FREE_POOL_Old = gBS->FreePool;
    gBS->FreePool = EFI_FREE_POOL_FUZZ;

    // Event & Timer Services
    EFI_CREATE_EVENT_Old = gBS->CreateEvent;
    gBS->CreateEvent = EFI_CREATE_EVENT_FUZZ;

    EFI_SET_TIMER_Old = gBS->SetTimer;
    gBS->SetTimer = EFI_SET_TIMER_FUZZ;

    EFI_WAIT_FOR_EVENT_Old = gBS->WaitForEvent;
    gBS->WaitForEvent = EFI_WAIT_FOR_EVENT_FUZZ;

    EFI_SIGNAL_EVENT_Old = gBS->SignalEvent;
    gBS->SignalEvent = EFI_SIGNAL_EVENT_FUZZ;

    EFI_CLOSE_EVENT_Old = gBS->CloseEvent;
    gBS->CloseEvent = EFI_CLOSE_EVENT_FUZZ;

    EFI_CHECK_EVENT_Old = gBS->CheckEvent;
    gBS->CheckEvent = EFI_CHECK_EVENT_FUZZ;

    // Protocol Handler Services
    EFI_INSTALL_PROTOCOL_INTERFACE_Old = gBS->InstallProtocolInterface;
    gBS->InstallProtocolInterface = EFI_INSTALL_PROTOCOL_INTERFACE_FUZZ;

    EFI_REINSTALL_PROTOCOL_INTERFACE_Old = gBS->ReinstallProtocolInterface;
    gBS->ReinstallProtocolInterface = EFI_REINSTALL_PROTOCOL_INTERFACE_FUZZ;

    EFI_UNINSTALL_PROTOCOL_INTERFACE_Old = gBS->UninstallProtocolInterface;
    gBS->UninstallProtocolInterface = EFI_UNINSTALL_PROTOCOL_INTERFACE_FUZZ;

    EFI_HANDLE_PROTOCOL_Old = gBS->HandleProtocol;
    gBS->HandleProtocol = EFI_HANDLE_PROTOCOL_FUZZ;

    EFI_REGISTER_PROTOCOL_NOTIFY_Old = gBS->RegisterProtocolNotify;
    gBS->RegisterProtocolNotify = EFI_REGISTER_PROTOCOL_NOTIFY_FUZZ;

    EFI_LOCATE_HANDLE_Old = gBS->LocateHandle;
    gBS->LocateHandle = EFI_LOCATE_HANDLE_FUZZ;

    EFI_LOCATE_DEVICE_PATH_Old = gBS->LocateDevicePath;
    gBS->LocateDevicePath = EFI_LOCATE_DEVICE_PATH_FUZZ;

    EFI_INSTALL_CONFIGURATION_TABLE_Old = gBS->InstallConfigurationTable;
    gBS->InstallConfigurationTable = EFI_INSTALL_CONFIGURATION_TABLE_FUZZ;

    // Image Services
    EFI_IMAGE_LOAD_Old = gBS->LoadImage;
    gBS->LoadImage = EFI_IMAGE_LOAD_FUZZ;

    EFI_IMAGE_START_Old = gBS->StartImage;
    gBS->StartImage = EFI_IMAGE_START_FUZZ;

    EFI_EXIT_Old = gBS->Exit;
    gBS->Exit = EFI_EXIT_FUZZ;

    EFI_IMAGE_UNLOAD_Old = gBS->UnloadImage;
    gBS->UnloadImage = EFI_IMAGE_UNLOAD_FUZZ;

    EFI_EXIT_BOOT_SERVICES_Old = gBS->ExitBootServices;
    gBS->ExitBootServices = EFI_EXIT_BOOT_SERVICES_FUZZ;

    // Miscellaneous Services
    EFI_GET_NEXT_MONOTONIC_COUNT_Old = gBS->GetNextMonotonicCount;
    gBS->GetNextMonotonicCount = EFI_GET_NEXT_MONOTONIC_COUNT_FUZZ;

    EFI_STALL_Old = gBS->Stall;
    gBS->Stall = EFI_STALL_FUZZ;

    EFI_SET_WATCHDOG_TIMER_Old = gBS->SetWatchdogTimer;
    gBS->SetWatchdogTimer = EFI_SET_WATCHDOG_TIMER_FUZZ;

    // DriverSupport Services
    EFI_CONNECT_CONTROLLER_Old = gBS->ConnectController;
    gBS->ConnectController = EFI_CONNECT_CONTROLLER_FUZZ;

    EFI_DISCONNECT_CONTROLLER_Old = gBS->DisconnectController;
    gBS->DisconnectController = EFI_DISCONNECT_CONTROLLER_FUZZ;

    // Open and Close Protocol Services
    EFI_OPEN_PROTOCOL_Old = gBS->OpenProtocol;
    gBS->OpenProtocol = EFI_OPEN_PROTOCOL_FUZZ;

    EFI_CLOSE_PROTOCOL_Old = gBS->CloseProtocol;
    gBS->CloseProtocol = EFI_CLOSE_PROTOCOL_FUZZ;

    EFI_OPEN_PROTOCOL_INFORMATION_Old = gBS->OpenProtocolInformation;
    gBS->OpenProtocolInformation = EFI_OPEN_PROTOCOL_INFORMATION_FUZZ;

    // Library Services
    EFI_PROTOCOLS_PER_HANDLE_Old = gBS->ProtocolsPerHandle;
    gBS->ProtocolsPerHandle = EFI_PROTOCOLS_PER_HANDLE_FUZZ;

    EFI_LOCATE_HANDLE_BUFFER_Old = gBS->LocateHandleBuffer;
    gBS->LocateHandleBuffer = EFI_LOCATE_HANDLE_BUFFER_FUZZ;

    EFI_LOCATE_PROTOCOL_Old = gBS->LocateProtocol;
    gBS->LocateProtocol = EFI_LOCATE_PROTOCOL_FUZZ;

    // 32-bit CRC Services
    EFI_CALCULATE_CRC32_Old = gBS->CalculateCrc32;
    gBS->CalculateCrc32 = EFI_CALCULATE_CRC32_FUZZ;

    // Miscellaneous Services
    EFI_COPY_MEM_Old = gBS->CopyMem;
    gBS->CopyMem = EFI_COPY_MEM_FUZZ;

    EFI_SET_MEM_Old = gBS->SetMem;
    gBS->SetMem = EFI_SET_MEM_FUZZ;

    EFI_CREATE_EVENT_EX_Old = gBS->CreateEventEx;
    gBS->CreateEventEx = EFI_CREATE_EVENT_EX_FUZZ;

    GetVariableOld = gST->RuntimeServices->GetVariable;
    gST->RuntimeServices->GetVariable = EFI_GET_VARIABLE_FUZZ;

    SetVariableOld = gST->RuntimeServices->SetVariable;
    gST->RuntimeServices->SetVariable = EFI_SET_VARIABLE_FUZZ;
}
EFI_STATUS
EFIAPI EFI_ACPI_GET_ACPI_TABLE_FUNC(
  IN EFI_ACPI_SUPPORT_PROTOCOL            *This,
  IN INTN                                 Index,
  OUT VOID                                **Table,
  OUT EFI_ACPI_TABLE_VERSION              *Version,
  OUT UINTN                               *Handle
  )
{
  return EFI_SUCCESS;
}
EFI_STATUS
EFIAPI EFI_ACPI_SET_ACPI_TABLE_FUNC(
  IN EFI_ACPI_SUPPORT_PROTOCOL            *This,
  IN VOID                                 *Table OPTIONAL,
  IN BOOLEAN                              Checksum,
  IN EFI_ACPI_TABLE_VERSION               Version,
  IN OUT UINTN                            *Handle
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI EFI_ACPI_PUBLISH_TABLES_FUNC(
  IN EFI_ACPI_SUPPORT_PROTOCOL            *This,
  IN EFI_ACPI_TABLE_VERSION               Version
  )
{
  return EFI_SUCCESS;
}
VOID *DxeBuffer;
UINT8 UnknownProtocol[1000];
PCH_NVS_AREA_PROTOCOL mPchNvsAreaProtocol;
SA_POLICY_PROTOCOL mSaPolicyProtocol;
DXE_CPU_POLICY_PROTOCOL mDxeCpuPolicyProcotol;
EFI_ACPI_SUPPORT_PROTOCOL mEfiAcpiSupportProtocol;
EFI_POWER_MGMT_INIT_DONE_PROTOCOL mEfiPowerMgmtInitDoneProtocol;
PLATFORM_NVS_AREA_PROTOCOL mPlatformNvsAreaProtocol;
CPU_NVS_AREA_PROTOCOL mCpuNvsAreProtocol;
CPU_GLOBAL_NVS_AREA_PROTOCOL mCpuGlobalNvsAreaProtocol;
EFI_SMBIOS_FLASH_DATA_PROTOCOL mAmiSmbiosFlashDataProtocol;
EFI_GLOBAL_NVS_AREA_PROTOCOL mGlobalNvsAreaProtocol;
EFI_BOOT_SCRIPT_SAVE_PROTOCOL mEfiBootScriptSaveProtocol;
SYSTEM_AGENT_GLOBAL_NVS_AREA_PROTOCOL mSaGlobalNvsAreaProtocol;
EFI_PLATFORMINFO_PROTOCOL mEfiPlatforminfoProtocol;
AMI_FLASH_PROTOCOL mAmiFlashProtocol;
EFI_SMI_FLASH_PROTOCOL mEfiSmiFlashProtocol;
EFI_HECI_PROTOCOL mEfiHeciProtocol;
AMI_PCI_EXT_PROTOCOL mAmiPciExtProtocol;
EFI_PCH_INFO_PROTOCOL mEfiPchInfoProtocol;
EFI_IIO_UDS_PROTOCOL mEfiIioUdsProtocol;
EFI_WHEA_SUPPORT_PROTOCOL mEfiWheaSupportProtocol;
PPM_PLATFORM_POLICY_PROTOCOL mPpmPlatformPolicyProtocol;
EFI_IIO_SYSTEM_PROTOCOL mEfiIioSystemProtocol;
EFI_USB2_HC_PROTOCOL mEfiUsb2HcProtocol;
AMI_TCG_PLATFORM_PROTOCOL mAmiTcgPlatformProtocol;
EFI_NB_ERROR_LOG_DISPATCH_PROTOCOL mEfiNbErrorLogDispatchProtocol;
MEM_INFO_PROTOCOL mMemInfoProtocol;
DXE_CPU_PLATFORM_POLICY_PROTOCOL mDxeCpuPlatformPolicyProtocol;
EFI_ALERT_STANDARD_FORMAT_PROTOCOL mEfiAlertStandardFormatProtocol;
DXE_PCH_PLATFORM_POLICY_PROTOCOL mDxePchPlatformPolicyProtocol;
AMI_SMBIOS_PROTOCOL mAmiSmbiosProtocol;
EFI_TCG_PROTOCOL mEfiTcgProtocol;
EFI_TREE_PROTOCOL mEfiTreeProtocol;
EFI_SYSTEM_USB_SUPPORT_POLICY_PROTOCOL mEfiSystemUsbSupportPolicyProtocol;
EFI_USB_PROTOCOL nEfiUsbProtocol;
EFI_SMBUS_HC_PROTOCOL mEfiSmbusHcProtocol;
EFI_STATUS
EFIAPI EFI_HECI_SENDWACK_FUNC (
  IN OUT  UINT32           *Message,
  IN OUT  UINT32           Length,
  IN OUT  UINT32           *RecLength,
  IN      UINT8            HostAddress,
  IN      UINT8            MEAddress
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI EFI_HECI_READ_MESSAGE_FUNC (
  IN      UINT32           Blocking,
  IN      UINT32           *MessageBody,
  IN OUT  UINT32           *Length
  )
{
  return EFI_SUCCESS;
}


EFI_STATUS
EFIAPI EFI_HECI_READ_FLUSH_MESSAGE_FUNC (
  IN      UINT32           Blocking
  )
{
  return EFI_SUCCESS;
}


EFI_STATUS
EFIAPI EFI_HECI_SEND_MESSAGE_FUNC (
  IN      UINT32           *Message,
  IN      UINT32           Length,
  IN      UINT8            HostAddress,
  IN      UINT8            MEAddress
  )
{
  return EFI_SUCCESS;
}


EFI_STATUS
EFIAPI EFI_HECI_RESET_FUNC (VOID)
{
  return EFI_SUCCESS;
}


EFI_STATUS
EFIAPI EFI_HECI_INIT_FUNC (VOID)
{
  return EFI_SUCCESS;
}



EFI_STATUS
EFIAPI EFI_HECI_REINIT_FUNC (VOID)
{
  return EFI_SUCCESS;
}



EFI_STATUS
EFIAPI EFI_HECI_RESET_WAIT_FUNC (
  IN        UINT32           Delay
  )
{
  return EFI_SUCCESS;
}



EFI_STATUS
EFIAPI EFI_HECI_GET_ME_STATUS_FUNC (
  IN UINT32                       *Status
  )
{
  return EFI_SUCCESS;
}



EFI_STATUS
EFIAPI EFI_HECI_GET_ME_MODE_FUNC (
  IN UINT32                       *Mode
  )
{
  return EFI_SUCCESS;
}


VOID* EFIAPI EFI_SMBIOS_GET_TABLE_ENTRY_FUNC () {
  return NULL;
}

VOID* EFIAPI EFI_SMBIOS_GET_SCRATCH_BUFFER_FUNC () {
  return NULL;
}

UINT16 EFIAPI EFI_SMBIOS_GET_BUFFER_MAX_SIZE_FUNC () {
  return 0;
}

UINT16 EFIAPI EFI_SMBIOS_GET_FREE_HANDLE_FUNC () {
  return 0;
}

EFI_STATUS EFIAPI EFI_SMBIOS_ADD_STRUCTURE_FUNC (
    IN UINT8        *Buffer,
    IN UINT16       Size
) {
  return EFI_SUCCESS;
}

EFI_STATUS EFIAPI EFI_SMBIOS_ADD_STRUC_HANDLE_FUNC (
    IN UINT16       Handle,
    IN UINT8        *Buffer,
    IN UINT16       Size
) {
  return EFI_SUCCESS;
}

EFI_STATUS EFIAPI EFI_SMBIOS_DELETE_STRUCTURE_FUNC (
    IN UINT16       Handle
) {
  return EFI_SUCCESS;
}

EFI_STATUS EFIAPI EFI_SMBIOS_READ_STRUCTURE_FUNC (
    IN      UINT16  Handle,
    IN OUT  UINT8   **BufferPtr,
    IN OUT  UINT16  *BufferSize
) {
  return EFI_SUCCESS;
}

EFI_STATUS EFIAPI EFI_SMBIOS_READ_STRUC_TYPE_FUNC (
    IN UINT8        Type,
    IN UINT8        Instance,
    IN UINT8        **BufferPtr,
    IN UINT16       *BufferSize
) {
  return EFI_SUCCESS;
}

EFI_STATUS EFIAPI EFI_SMBIOS_WRITE_STRUCTURE_FUNC (
    IN UINT16       Handle,
    IN UINT8        *BufferPtr,
    IN UINT16       BufferSize
) {
  return EFI_SUCCESS;
}

EFI_STATUS EFIAPI EFI_SMBIOS_ADD_STRUC_INDEX_FUNC (
    IN UINT16       Handle,
    IN UINT8        *Buffer,
    IN UINT16       Size,
    IN UINT16       Index
) {
  return EFI_SUCCESS;
}

EFI_STATUS EFIAPI EFI_SMBIOS_UPDATE_HEADER_FUNC (
) {
  return EFI_SUCCESS;
}

VOID* EFIAPI EFI_SMBIOS_GET_VER_TABLE_ENTRY_FUNC (
    IN UINT8                  SmbiosMajorVersion
) {
  return NULL;
}

EFI_STATUS EFIAPI EFI_UNKNOWN1_FUNC (
) {
  return EFI_SUCCESS;
}

EFI_STATUS EFIAPI EFI_BOOT_SCRIPT_WRITE_FUNC (
  IN EFI_BOOT_SCRIPT_SAVE_PROTOCOL            * This,
  IN UINT16                                   TableName,
  IN UINT16                                   OpCode,
  ...
  )
{
  return EFI_SUCCESS; 
}
EFI_STATUS EFIAPI EFI_BOOT_SCRIPT_CLOSE_TABLE_FUNC (
  IN EFI_BOOT_SCRIPT_SAVE_PROTOCOL            * This,
  IN UINT16                                   TableName,
  OUT EFI_PHYSICAL_ADDRESS                    * Address
  )
{
  return EFI_SUCCESS; 
}
EFI_STATUS EFIAPI EFI_PLATFORMINFO_GET_PLATFORMINFO_FUNC (
    IN EFI_PLATFORMINFO_PROTOCOL *This,
    OUT EFI_PLATFORMINFO_PLATFORM_INFO_TYPE *PlatformInfo)
{
  return EFI_SUCCESS; 
}
EFI_STATUS EFIAPI EFI_PLATFORMINFO_GET_KEYVALUE_FUNC (
    IN EFI_PLATFORMINFO_PROTOCOL *This,
    IN EFI_PLATFORMINFO_KEY_TYPE Key,
    OUT UINT32 *Value)
{
  return EFI_SUCCESS; 
}


EFI_STATUS EFIAPI AMI_FLASH_READ_FUNC(
    IN     VOID     *FlashAddress, 
    IN     UINTN    Size, 
    IN OUT VOID     *DataBuffer
)
{
  return EFI_SUCCESS; 
}

EFI_STATUS EFIAPI AMI_FLASH_ERASE_FUNC(
    IN VOID *FlashAddress, 
    IN UINTN Size
)
{
  return EFI_SUCCESS; 
}

EFI_STATUS EFIAPI AMI_FLASH_WRITE_FUNC(
    IN  VOID *FlashAddress, 
    IN  UINTN Size, 
    IN  VOID *DataBuffer
)
{
  return EFI_SUCCESS;   
}

EFI_STATUS EFIAPI AMI_FLASH_UPDATE_FUNC(
    IN  VOID *FlashAddress, 
    IN  UINTN Size, 
    IN  VOID *DataBuffer
)
{
  return EFI_SUCCESS;    
}

EFI_STATUS EFIAPI AMI_FLASH_WRITE_ENABLE_FUNC(VOID)
{
  return EFI_SUCCESS;  
}

/**
  Disable the ability to write to the flash part.
**/
EFI_STATUS EFIAPI AMI_FLASH_WRITE_DISABLE_FUNC(VOID)
{
  return EFI_SUCCESS;   
}

EFI_STATUS GET_FLASH_INFO_FUNC (
    IN OUT INFO_BLOCK           *InfoBlock
)
{
  return EFI_SUCCESS;  
}

EFI_STATUS ENABLE_FLASH_FUNC (
    IN OUT FUNC_BLOCK           *FuncBlock
)
{
  return EFI_SUCCESS;  
}

EFI_STATUS DISABLE_FLASH_FUNC (
    IN OUT FUNC_BLOCK           *FuncBlock
)
{
  return EFI_SUCCESS;  
}

EFI_STATUS READ_FLASH_FUNC(
    IN OUT FUNC_BLOCK           *FuncBlock
)
{
  return EFI_SUCCESS;  
}

EFI_STATUS WRITE_FLASH_FUNC (
    IN OUT FUNC_BLOCK           *FuncBlock
)
{
  return EFI_SUCCESS;  
}

EFI_STATUS ERASE_FLASH_FUNC (
    IN OUT FUNC_BLOCK           *FuncBlock
)
{
  return EFI_SUCCESS;  
}


EFI_STATUS EFIAPI  AMI_PCI_EXT_IS_PCI_EXPRESS_FUNC(
	IN  AMI_PCI_EXT_PROTOCOL	              			*This,
	IN  EFI_HANDLE                               		PciDeviceHandle,
	IN  VOID								*PciIo 		    OPTIONAL,
    OUT VOID                                       **PciExpData    OPTIONAL
)
{
  return EFI_SUCCESS;  
}


//-------------------------------------------------
EFI_STATUS EFIAPI  AMI_PCI_EXT_IS_PCI_X_FUNC(
	IN  AMI_PCI_EXT_PROTOCOL	              			*This,
	IN  EFI_HANDLE                               		PciDeviceHandle,
	IN  VOID								*PciIo 		    OPTIONAL,
    OUT VOID                                       **PciXData    OPTIONAL
)
{
  return EFI_SUCCESS;  
}


//-------------------------------------------------
EFI_STATUS EFIAPI  AMI_PCI_EXT_IS_P2P_BRG_FUNC(
	IN  AMI_PCI_EXT_PROTOCOL	              			*This,
	IN  EFI_HANDLE                               		PciDeviceHandle,
	IN  VOID								*PciIo 		    OPTIONAL,
    OUT VOID                                     **BrgData       OPTIONAL
)
{
  return EFI_SUCCESS;  
}


//-------------------------------------------------
EFI_STATUS EFIAPI  AMI_PCI_EXT_IS_CRD_BRG_FUNC(
	IN  AMI_PCI_EXT_PROTOCOL	              			*This,
	IN  EFI_HANDLE                               		PciDeviceHandle,
	IN  VOID								*PciIo 		    OPTIONAL,
    OUT VOID                                     **BrgData       OPTIONAL
)
{
  return EFI_SUCCESS;  
}


//-------------------------------------------------
EFI_STATUS EFIAPI  AMI_PCI_EXT_IS_REG_DEVICE_FUNC(
	IN  AMI_PCI_EXT_PROTOCOL	              			*This,
	IN  EFI_HANDLE                               		PciDeviceHandle,
	IN  VOID								*PciIo 		OPTIONAL
)
{
  return EFI_SUCCESS;  
}


EFI_STATUS EFIAPI  AMI_PCI_EXT_GET_CLASS_CODES_INFO_FUNC(
	IN  AMI_PCI_EXT_PROTOCOL	              			*This,
	IN  EFI_HANDLE                               		PciDeviceHandle,
	IN  VOID								*PciIo 		OPTIONAL,
	OUT VOID									*CassCodes
)
{
  return EFI_SUCCESS;  
}


EFI_STATUS EFIAPI  AMI_PCI_EXT_GET_PCI_PIC_IRQ_FUNC(
	IN  AMI_PCI_EXT_PROTOCOL	              			*This,
	IN  EFI_HANDLE                               		PciDeviceHandle,
	IN  VOID								*PciIo 		OPTIONAL,
    OUT VOID                               **PicIrqTblEntry,
    VOID                       **ParentDevices,
    OUT UINTN                                           *EntryCount
)
{
  return EFI_SUCCESS;  
}


EFI_STATUS EFIAPI  AMI_PCI_EXT_GET_PCI_APIC_IRQ_FUNC(
	IN  AMI_PCI_EXT_PROTOCOL	              			*This,
	IN  EFI_HANDLE                               		PciDeviceHandle,
	IN  VOID								*PciIo 		OPTIONAL,
    OUT VOID                              **ApicIrqTblEntry,
    VOID                       **ParentDevices,
    OUT UINTN                                           *EntryCount
)
{
  return EFI_SUCCESS;  
}

EFI_STATUS
EFIAPI IIH_ENABLE_VC_FUNC (
  IN EFI_IIO_UDS_PROTOCOL     *This,
  IN UINT32                    VcCtrlData
  )
{
  return EFI_SUCCESS;  
}



EFI_STATUS
EFIAPI EFI_ADD_ERROR_SOURCE_FUNC (
  IN EFI_WHEA_SUPPORT_PROTOCOL          *This,
  IN WHEA_ERROR_TYPE                    Type,
  IN UINTN                              Flags,
  IN BOOLEAN                            EnableError,
  OUT UINT16                            *SourceID,
  IN UINTN                              NoOfRecords,
  IN UINTN                              MaxSections,
  IN VOID                               *SourceData
  )
{
  return EFI_SUCCESS;  
}


//
// Add an last boot error data log to WHEA for error that happend on last boot.
//

EFI_STATUS
EFIAPI EFI_ADD_BOOT_ERROR_LOG_FUNC (
  IN EFI_WHEA_SUPPORT_PROTOCOL          *This,
  IN UINT8                              ErrorCondtion,
  IN UINT32                             ErrorSevirity,
  OPTIONAL IN EFI_GUID                  *FruID, 
  OPTIONAL IN CHAR8                     *FruDescription,
  IN EFI_GUID                           *ErrorType, 
  IN UINT32                             ErrorDataSize, 
  OPTIONAL IN UINT8                     *ErrorData
  )
{
  return EFI_SUCCESS;  
}


//
// This funtion will install serialization instruction for error injection method for an error type (e.g. memory UE).
// If error injection method already exist for the error type, the old method will be replced with new one.
//

EFI_STATUS
EFIAPI EFI_INSTALL_ERROR_INJECTION_METHOD_FUNC (
  IN EFI_WHEA_SUPPORT_PROTOCOL          *This,
  IN UINTN                              ErrorType,
  IN UINTN                              InstCount,
  IN VOID                               *InstEntry
  )
{
  return EFI_SUCCESS;  
}


//
// Tis function will get the current error injection capability installed in a bitmap.
//

EFI_STATUS
EFIAPI EFI_GET_ERROR_INJECTION_CAPABILITY_FUNC (
  IN EFI_WHEA_SUPPORT_PROTOCOL          *This,
  OUT UINTN                             *InjectCapability
  )
{
  return EFI_SUCCESS;  
}


//
// Returns the Error log Address Range allocated for WHEA
//

EFI_STATUS
EFIAPI EFI_GET_ELAR_FUNC (
  IN EFI_WHEA_SUPPORT_PROTOCOL          *This,
  OUT UINTN                             *ElarSize,
  OUT VOID                              **LogAddress
  )
{
  return EFI_SUCCESS;  
}


//
// This installs the serialization actions for accessing Error Record persitant Storage.
//

EFI_STATUS
EFIAPI EFI_INSTALL_ERROR_RECORD_METHOD_FUNC (
  IN EFI_WHEA_SUPPORT_PROTOCOL          *This,
  IN UINTN                            InstCount,
  IN VOID                           *InstEntry
  )
{
  return EFI_SUCCESS;  
}
EFI_STATUS
EFIAPI IIO_GET_CPU_UPLINK_PORT_FUNC (
  IN  UINT8             IioIndex,
  OUT PORT_DESCRIPTOR   *PortDescriptor,
  OUT BOOLEAN           *PortStatus,
  OUT PORT_ATTRIB       *PortAttrib
)
{
  return EFI_SUCCESS;  
}
EFI_STATUS
EFIAPI EFI_USB2_HC_PROTOCOL_GET_CAPABILITY_FUNC (
  IN  EFI_USB2_HC_PROTOCOL  *This,
  OUT UINT8                 *MaxSpeed,
  OUT UINT8                 *PortNumber,
  OUT UINT8                 *Is64BitCapable
  )
{
  return EFI_SUCCESS;  
}
EFI_STATUS
EFIAPI EFI_USB2_HC_PROTOCOL_RESET_FUNC (
  IN EFI_USB2_HC_PROTOCOL   *This,
  IN UINT16                 Attributes
  )
{
  return EFI_SUCCESS;  
}
EFI_STATUS
EFIAPI EFI_USB2_HC_PROTOCOL_GET_STATE_FUNC (
  IN  EFI_USB2_HC_PROTOCOL    *This,
  OUT EFI_USB_HC_STATE        *State
  )
{
  return EFI_SUCCESS;  
}
EFI_STATUS
EFIAPI EFI_USB2_HC_PROTOCOL_SET_STATE_FUNC (
  IN EFI_USB2_HC_PROTOCOL    *This,
  IN EFI_USB_HC_STATE        State
  )
{
  return EFI_SUCCESS;  
}
EFI_STATUS
EFIAPI EFI_USB2_HC_PROTOCOL_CONTROL_TRANSFER_FUNC (
  IN     EFI_USB2_HC_PROTOCOL               *This,
  IN     UINT8                              DeviceAddress,
  IN     UINT8                              DeviceSpeed,
  IN     UINTN                              MaximumPacketLength,
  IN     EFI_USB_DEVICE_REQUEST             *Request,
  IN     EFI_USB_DATA_DIRECTION             TransferDirection,
  IN OUT VOID                               *Data       OPTIONAL,
  IN OUT UINTN                              *DataLength OPTIONAL,
  IN     UINTN                              TimeOut,
  IN     EFI_USB2_HC_TRANSACTION_TRANSLATOR *Translator,
  OUT    UINT32                             *TransferResult
  )
{
  return EFI_SUCCESS;  
}
EFI_STATUS
EFIAPI EFI_USB2_HC_PROTOCOL_BULK_TRANSFER_FUNC (
  IN     EFI_USB2_HC_PROTOCOL               *This,
  IN     UINT8                              DeviceAddress,
  IN     UINT8                              EndPointAddress,
  IN     UINT8                              DeviceSpeed,
  IN     UINTN                              MaximumPacketLength,
  IN     UINT8                              DataBuffersNumber,
  IN OUT VOID                               *Data[EFI_USB_MAX_BULK_BUFFER_NUM],
  IN OUT UINTN                              *DataLength,
  IN OUT UINT8                              *DataToggle,
  IN     UINTN                              TimeOut,
  IN     EFI_USB2_HC_TRANSACTION_TRANSLATOR *Translator,
  OUT    UINT32                             *TransferResult
  )
{
  return EFI_SUCCESS;  
}
EFI_STATUS
EFIAPI EFI_USB2_HC_PROTOCOL_ASYNC_INTERRUPT_TRANSFER_FUNC (
  IN     EFI_USB2_HC_PROTOCOL                                *This,
  IN     UINT8                                               DeviceAddress,
  IN     UINT8                                               EndPointAddress,
  IN     UINT8                                               DeviceSpeed,
  IN     UINTN                                               MaxiumPacketLength,
  IN     BOOLEAN                                             IsNewTransfer,
  IN OUT UINT8                                               *DataToggle,
  IN     UINTN                                               PollingInterval  OPTIONAL,
  IN     UINTN                                               DataLength       OPTIONAL,
  IN     EFI_USB2_HC_TRANSACTION_TRANSLATOR *Translator,
  IN     EFI_ASYNC_USB_TRANSFER_CALLBACK                     CallBackFunction OPTIONAL,
  IN     VOID                                                *Context         OPTIONAL
  )
{
  return EFI_SUCCESS;  
}
EFI_STATUS
EFIAPI EFI_USB2_HC_PROTOCOL_SYNC_INTERRUPT_TRANSFER_FUNC (
  IN     EFI_USB2_HC_PROTOCOL   *This,
  IN     UINT8                  DeviceAddress,
  IN     UINT8                  EndPointAddress,
  IN     UINT8                  DeviceSpeed,
  IN     UINTN                  MaximumPacketLength,
  IN OUT VOID                   *Data,
  IN OUT UINTN                  *DataLength,
  IN OUT UINT8                  *DataToggle,
  IN     UINTN                  TimeOut,
  IN     EFI_USB2_HC_TRANSACTION_TRANSLATOR *Translator,
  OUT    UINT32                 *TransferResult
  )
{
  return EFI_SUCCESS;  
}
EFI_STATUS
EFIAPI EFI_USB2_HC_PROTOCOL_ISOCHRONOUS_TRANSFER_FUNC (
  IN     EFI_USB2_HC_PROTOCOL               *This,
  IN     UINT8                              DeviceAddress,
  IN     UINT8                              EndPointAddress,
  IN     UINT8                              DeviceSpeed,
  IN     UINTN                              MaximumPacketLength,
  IN     UINT8                              DataBuffersNumber,
  IN OUT VOID                               *Data[EFI_USB_MAX_ISO_BUFFER_NUM],
  IN     UINTN                              DataLength,
  IN     EFI_USB2_HC_TRANSACTION_TRANSLATOR *Translator,
  OUT    UINT32                             *TransferResult
  )
{
  return EFI_SUCCESS;  
}
EFI_STATUS
EFIAPI EFI_USB2_HC_PROTOCOL_ASYNC_ISOCHRONOUS_TRANSFER_FUNC (
  IN     EFI_USB2_HC_PROTOCOL               *This,
  IN     UINT8                              DeviceAddress,
  IN     UINT8                              EndPointAddress,
  IN     UINT8                              DeviceSpeed,
  IN     UINTN                              MaximumPacketLength,
  IN     UINT8                              DataBuffersNumber,
  IN OUT VOID                               *Data[EFI_USB_MAX_ISO_BUFFER_NUM],
  IN     UINTN                              DataLength,
  IN     EFI_USB2_HC_TRANSACTION_TRANSLATOR *Translator,
  IN     EFI_ASYNC_USB_TRANSFER_CALLBACK    IsochronousCallBack,
  IN     VOID                               *Context OPTIONAL
  )
{
  return EFI_SUCCESS;  
}
EFI_STATUS
EFIAPI EFI_USB2_HC_PROTOCOL_GET_ROOTHUB_PORT_STATUS_FUNC (
  IN EFI_USB2_HC_PROTOCOL    *This,
  IN  UINT8                  PortNumber,
  OUT EFI_USB_PORT_STATUS    *PortStatus
  )
{
  return EFI_SUCCESS;  
}
EFI_STATUS
EFIAPI EFI_USB2_HC_PROTOCOL_SET_ROOTHUB_PORT_FEATURE_FUNC (
  IN EFI_USB2_HC_PROTOCOL    *This,
  IN UINT8                   PortNumber,
  IN EFI_USB_PORT_FEATURE    PortFeature
  )
{
  return EFI_SUCCESS;  
}
EFI_STATUS
EFIAPI EFI_USB2_HC_PROTOCOL_CLEAR_ROOTHUB_PORT_FEATURE_FUNC (
  IN EFI_USB2_HC_PROTOCOL    *This,
  IN UINT8                   PortNumber,
  IN EFI_USB_PORT_FEATURE    PortFeature
  )
{
  return EFI_SUCCESS;  
}


EFI_STATUS
EFIAPI MEASURE_CPU_MICROCODE_FUNC (

)
{
  return EFI_SUCCESS;  
}

EFI_STATUS
EFIAPI MEASURE_PCI_OPROMS_FUNC (

)
{
  return EFI_SUCCESS;  
}


EFI_STATUS
EFIAPI PROCESS_TCG_SETUP_FUNC (

)
{
  return EFI_SUCCESS;  
}


EFI_STATUS
EFIAPI PROCESS_TCG_PPI_REQUEST_FUNC (

)
{
  return EFI_SUCCESS;  
}


EFI_STATUS
EFIAPI TCG_READY_TO_BOOT_FUNC (

)
{
  return EFI_SUCCESS;  
}


EFI_STATUS
EFIAPI GET_PROTOCOL_VERSION_FUNC (
    AMI_TCG_PROTOCOL_VERSION *a
)
{
  return EFI_SUCCESS;  
}

VOID
EFIAPI RESETOSTCGVAR_FUNC (
)
{
  return;
}
EFI_STATUS EFIAPI EFI_NB_ERROR_LOG_REGISTER_FUNC (
    IN EFI_NB_ERROR_LOG_DISPATCH_PROTOCOL   *This,
    IN EFI_NB_ERROR_LOG_DISPATCH            DispatchFunction,
    OUT EFI_HANDLE                          *DispatchHandle
)
{
  return EFI_SUCCESS;  
}

EFI_STATUS EFIAPI EFI_NB_ERROR_LOG_UNREGISTER_FUNC (
    IN EFI_NB_ERROR_LOG_DISPATCH_PROTOCOL   *This,
    IN EFI_HANDLE                           DispatchHandle
)
{
  return EFI_SUCCESS;  
}
EFI_STATUS
EFIAPI PLATFORM_CPU_RETRIEVE_MICROCODE_FUNC (
  IN DXE_CPU_PLATFORM_POLICY_PROTOCOL *This,
  OUT UINT8                           **MicrocodeData
  )
{
  return EFI_SUCCESS;  
}

EFI_STATUS
EFIAPI PLATFORM_CPU_GET_MAX_COUNT_FUNC (
  IN DXE_CPU_PLATFORM_POLICY_PROTOCOL *This,
  OUT UINT32                          *MaxThreadsPerCore,
  OUT UINT32                          *MaxCoresPerDie,
  OUT UINT32                          *MaxDiesPerPackage,
  OUT UINT32                          *MaxPackages
  )
{
  return EFI_SUCCESS;  
}
EFI_STATUS
EFIAPI PLATFORM_CPU_GET_CPU_INFO_FUNC (
  IN DXE_CPU_PLATFORM_POLICY_PROTOCOL *This,
  IN CPU_PHYSICAL_LOCATION            *Location,
  IN OUT PLATFORM_CPU_INFORMATION     *PlatformCpuInfo
  )
{
  return EFI_SUCCESS;  
}

EFI_STATUS
EFIAPI EFI_ALERT_STANDARD_FORMAT_PROTOCOL_GET_SMBUSADDR_FUNC (
  IN  EFI_ALERT_STANDARD_FORMAT_PROTOCOL   * This,
  OUT UINTN                                *SmbusDeviceAddress
  )
{
  return EFI_SUCCESS;  
}


EFI_STATUS
EFIAPI EFI_ALERT_STANDARD_FORMAT_PROTOCOL_SET_SMBUSADDR_FUNC (
  IN  EFI_ALERT_STANDARD_FORMAT_PROTOCOL   * This,
  IN  UINTN                                SmbusDeviceAddress
  )
{
  return EFI_SUCCESS;  
}


EFI_STATUS
EFIAPI EFI_ALERT_STANDARD_FORMAT_PROTOCOL_GET_BOOT_OPTIONS_FUNC (
  IN      EFI_ALERT_STANDARD_FORMAT_PROTOCOL   * This,
  IN  OUT EFI_ASF_BOOT_OPTIONS                 **AsfBootOptions
  )
{
  *AsfBootOptions = DxeBuffer;
  return EFI_SUCCESS;  
}


EFI_STATUS
EFIAPI EFI_ALERT_STANDARD_FORMAT_PROTOCOL_SEND_ASF_MESSAGE_FUNC (
  IN  EFI_ALERT_STANDARD_FORMAT_PROTOCOL   * This,
  IN  EFI_ASF_MESSAGE                      * AsfMessage
  )
{
  return EFI_SUCCESS;  
}

EFI_STATUS
EFIAPI EFI_TREE_GET_CAPABILITY_FUNC (
  IN EFI_TREE_PROTOCOL                *This,
  IN OUT TREE_BOOT_SERVICE_CAPABILITY *ProtocolCapability
  )
{
  ProtocolCapability->TrEEPresentFlag = FALSE;
  return EFI_SUCCESS;  
}

EFI_STATUS
EFIAPI EFI_TREE_GET_EVENT_LOG_FUNC (
  IN EFI_TREE_PROTOCOL     *This,
  IN TREE_EVENT_LOG_FORMAT EventLogFormat,
  OUT EFI_PHYSICAL_ADDRESS *EventLogLocation,
  OUT EFI_PHYSICAL_ADDRESS *EventLogLastEntry,
  OUT BOOLEAN              *EventLogTruncated
  )
{
  return EFI_SUCCESS;  
}

EFI_STATUS
EFIAPI EFI_TREE_HASH_LOG_EXTEND_EVENT_FUNC (
  IN EFI_TREE_PROTOCOL    *This,
  IN UINT64               Flags,
  IN EFI_PHYSICAL_ADDRESS DataToHash,
  IN UINT64               DataToHashLen,
  IN TrEE_EVENT           *Event
  )
{
  return EFI_SUCCESS;  
}

EFI_STATUS
EFIAPI EFI_TREE_SUBMIT_COMMAND_FUNC (
  IN EFI_TREE_PROTOCOL *This,
  IN UINT32            InputParameterBlockSize,
  IN UINT8             *InputParameterBlock,
  IN UINT32            OutputParameterBlockSize,
  IN UINT8             *OutputParameterBlock
  )
{
  return EFI_SUCCESS;  
}
EFI_STATUS GET_FLASH_TABLE_INFO_FUNC (
    IN  EFI_SMBIOS_FLASH_DATA_PROTOCOL  *This,
    OUT VOID                            **Location,
    OUT UINT32                          *Size
)
{
  return EFI_SUCCESS;  
}

EFI_STATUS GET_FIELD_FUNC (
    IN  EFI_SMBIOS_FLASH_DATA_PROTOCOL  *This,
    IN  UINT8                           Table,
    IN  UINT8                           Offset,
    OUT VOID                            **String
)
{
  return EFI_SUCCESS;  
}
EFI_STATUS
EFIAPI EFI_TCG_STATUS_CHECK_FUNC(
  IN      EFI_TCG_PROTOCOL          *This,
  OUT     TCG_EFI_BOOT_SERVICE_CAPABILITY
  *ProtocolCapability,
  OUT     UINT32                    *TCGFeatureFlags,
  OUT     EFI_PHYSICAL_ADDRESS      *EventLogLocation,
  OUT     EFI_PHYSICAL_ADDRESS      *EventLogLastEntry
  )
{
  return EFI_SUCCESS;  
}
EFI_STATUS
EFIAPI EFI_TCG_HASH_ALL_FUNC(
  IN      EFI_TCG_PROTOCOL          *This,
  IN      UINT8                     *HashData,
  IN      UINT64                    HashDataLen,
  IN      TCG_ALGORITHM_ID          AlgorithmId,
  IN OUT  UINT64                    *HashedDataLen,
  IN OUT  UINT8                     **HashedDataResult
  )
{
  return EFI_SUCCESS;  
}
EFI_STATUS
EFIAPI EFI_TCG_LOG_EVENT_FUNC(
  IN      EFI_TCG_PROTOCOL          *This,
  IN      TCG_PCR_EVENT             *TCGLogData,
  IN OUT  UINT32                    *EventNumber,
  IN      UINT32                    Flags
)
{
  return EFI_SUCCESS;  
}
EFI_STATUS
EFIAPI EFI_TCG_PASS_THROUGH_TO_TPM_FUNC(
  IN      EFI_TCG_PROTOCOL          *This,
  IN      UINT32                    TpmInputParameterBlockSize,
  IN      UINT8                     *TpmInputParameterBlock,
  IN      UINT32                    TpmOutputParameterBlockSize,
  IN      UINT8                     *TpmOutputParameterBlock
  )
{
  return EFI_SUCCESS;  
}
EFI_STATUS
EFIAPI EFI_TCG_HASH_LOG_EXTEND_EVENT_FUNC(
  IN      EFI_TCG_PROTOCOL          *This,
  IN      EFI_PHYSICAL_ADDRESS      HashData,
  IN      UINT64                    HashDataLen,
  IN      TCG_ALGORITHM_ID          AlgorithmId,
  IN OUT  TCG_PCR_EVENT             *TCGLogData,
  IN OUT  UINT32                    *EventNumber,
  OUT  EFI_PHYSICAL_ADDRESS      *EventLogLastEntry
  )
{
  return EFI_SUCCESS;  
}
EFI_STATUS
EFIAPI EFI_USB_SUPPORT_FUNC (
  IN  EFI_SYSTEM_USB_SUPPORT_POLICY_PROTOCOL   * This,
  IN  UINTN                      * Arg1,
  OUT UINTN                      * Arg2
)
{
  *Arg2 = 1;
  return EFI_SUCCESS;  
}

EFI_STATUS
EFIAPI EFI_SMBUS_HC_EXECUTE_OPERATION_FUNC (
  IN CONST  EFI_SMBUS_HC_PROTOCOL     *This,
  IN        EFI_SMBUS_DEVICE_ADDRESS  SlaveAddress,
  IN        EFI_SMBUS_DEVICE_COMMAND  Command,
  IN        EFI_SMBUS_OPERATION       Operation,
  IN        BOOLEAN                   PecCheck,
  IN OUT    UINTN                     *Length,
  IN OUT    VOID                      *Buffer
){
  return EFI_SUCCESS;  
}


EFI_STATUS
EFIAPI EFI_SMBUS_HC_PROTOCOL_ARP_DEVICE_FUNC (
  IN CONST  EFI_SMBUS_HC_PROTOCOL     *This,
  IN        BOOLEAN                   ArpAll,
  IN        EFI_SMBUS_UDID            *SmbusUdid,   OPTIONAL
  IN OUT    EFI_SMBUS_DEVICE_ADDRESS  *SlaveAddress OPTIONAL
){
  return EFI_SUCCESS;   
}


EFI_STATUS
EFIAPI EFI_SMBUS_HC_PROTOCOL_GET_ARP_MAP_FUNC (
  IN CONST  EFI_SMBUS_HC_PROTOCOL   *This,
  IN OUT    UINTN                   *Length,
  IN OUT    EFI_SMBUS_DEVICE_MAP    **SmbusDeviceMap
){
  return EFI_SUCCESS;  
}



EFI_STATUS
EFIAPI EFI_SMBUS_NOTIFY_FUNCTION_FUNC (
  IN        EFI_SMBUS_DEVICE_ADDRESS  SlaveAddress,
  IN        UINTN                     Data
){
  return EFI_SUCCESS;  
}


EFI_STATUS
EFIAPI EFI_SMBUS_HC_PROTOCOL_NOTIFY_FUNC (
  IN CONST  EFI_SMBUS_HC_PROTOCOL     *This,
  IN        EFI_SMBUS_DEVICE_ADDRESS  SlaveAddress,
  IN        UINTN                     Data,
  IN        EFI_SMBUS_NOTIFY_FUNCTION NotifyFunction
){
  return EFI_SUCCESS; 
}


EFI_STATUS EFIAPI UNKNOWN_FUNC_DUMMY()
{
  return EFI_SUCCESS;
}
VOID InstallSmmFuzzProtocol();
VOID InstallSmmFuzzProtocol() {

  DxeBuffer = AllocatePool(0x50000);
  LIBAFL_QEMU_SMM_REPORT_DXE_BUFFER((UINTN)DxeBuffer,0x50000);

  EFI_HANDLE Handle = NULL;
  EFI_STATUS Status;
  SmmFuzzGlobalData.in_fuzz = 0;
  SmmFuzzGlobalData.dxe_module_info = AllocatePool(sizeof(DXE_MODULE_INFOS));
  ZeroMem (SmmFuzzGlobalData.dxe_module_info, sizeof(DXE_MODULE_INFOS));
  DXE_MODULE_INFOS *Info = (DXE_MODULE_INFOS *)SmmFuzzGlobalData.dxe_module_info;
  CopyGuid(&Info->Modules[Info->NumModules].Guid, gDxeCoreFileName);
  Info->Modules[Info->NumModules].StartAddress = (UINTN)gDxeCoreLoadedImage->ImageBase;
  Info->Modules[Info->NumModules].Size = gDxeCoreLoadedImage->ImageSize;
  Info->NumModules++;
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &Handle,
                  &gSmmFuzzDataProtocolGuid,
                  &SmmFuzzGlobalData,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);

  
  mPchNvsAreaProtocol.Area = DxeBuffer;
  ASSERT(sizeof(PCH_NVS_AREA) < 0x50000);
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &Handle,
                  &gPchNvsAreaProtocolGuid,
                  &mPchNvsAreaProtocol,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);

  mCpuGlobalNvsAreaProtocol.Area = DxeBuffer;
  ASSERT(sizeof(CPU_GLOBAL_NVS_AREA) < 0x50000);
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &Handle,
                  &gCpuGlobalNvsAreaProtocolGuid,
                  &mCpuGlobalNvsAreaProtocol,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);

  ASSERT(sizeof(SA_POLICY_PROTOCOL) < 0x50000);
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &Handle,
                  &gSaPolicyProtocolGuid,
                  DxeBuffer,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);

  ASSERT(sizeof(DXE_CPU_POLICY_PROTOCOL) < 0x50000);
  // mDxeCpuPolicyProcotol.EnableDts = 3;
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &Handle,
                  &gDxeCpuPolicyProtocolGuid,
                  DxeBuffer,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);

  mAmiSmbiosFlashDataProtocol.GetField = GET_FIELD_FUNC;
  mAmiSmbiosFlashDataProtocol.GetFlashTableInfo = GET_FLASH_TABLE_INFO_FUNC;
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &Handle,
                  &gAmiSmbiosFlashDataProtocolGuid,
                  &mAmiSmbiosFlashDataProtocol,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);


  mEfiAcpiSupportProtocol.GetAcpiTable = EFI_ACPI_GET_ACPI_TABLE_FUNC;
  mEfiAcpiSupportProtocol.SetAcpiTable = EFI_ACPI_SET_ACPI_TABLE_FUNC;
  mEfiAcpiSupportProtocol.PublishTables = EFI_ACPI_PUBLISH_TABLES_FUNC;
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &Handle,
                  &gEfiAcpiSupportProtocolGuid,
                  &mEfiAcpiSupportProtocol,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);

  ASSERT(sizeof(EFI_POWER_MGMT_INIT_DONE_PROTOCOL) < 0x50000);
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &Handle,
                  &gPowerMgmtInitDoneProtocolGuid,
                  DxeBuffer,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);

  mPlatformNvsAreaProtocol.Area = DxeBuffer;
  ASSERT(sizeof(PLATFORM_NVS_AREA) < 0x50000);
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &Handle,
                  &gPlatformNvsAreaProtocolGuid,
                  &mPlatformNvsAreaProtocol,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);

  mCpuNvsAreProtocol.Area = DxeBuffer;
  ASSERT(sizeof(CPU_NVS_AREA) < 0x50000);
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &Handle,
                  &gCpuNvsAreaProtocolGuid,
                  &mCpuNvsAreProtocol,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);

  mAmiSmbiosProtocol.SmbiosGetTableEntryPoint = EFI_SMBIOS_GET_TABLE_ENTRY_FUNC;
  mAmiSmbiosProtocol.SmbiosGetScratchBufferPtr = EFI_SMBIOS_GET_SCRATCH_BUFFER_FUNC;
  mAmiSmbiosProtocol.SmbiosGetBufferMaxSize = EFI_SMBIOS_GET_BUFFER_MAX_SIZE_FUNC;
  mAmiSmbiosProtocol.SmbiosGetFreeHandle = EFI_SMBIOS_GET_FREE_HANDLE_FUNC;
  mAmiSmbiosProtocol.SmbiosAddStructure = EFI_SMBIOS_ADD_STRUCTURE_FUNC;
  mAmiSmbiosProtocol.SmbiosAddStrucByHandle = EFI_SMBIOS_ADD_STRUC_HANDLE_FUNC;
  mAmiSmbiosProtocol.SmbiosDeleteStructure = EFI_SMBIOS_DELETE_STRUCTURE_FUNC;
  mAmiSmbiosProtocol.SmbiosReadStructure = EFI_SMBIOS_READ_STRUCTURE_FUNC;
  mAmiSmbiosProtocol.SmbiosReadStrucByType = EFI_SMBIOS_READ_STRUC_TYPE_FUNC;
  mAmiSmbiosProtocol.SmbiosWriteStructure = EFI_SMBIOS_WRITE_STRUCTURE_FUNC;
  mAmiSmbiosProtocol.SmbiosAddStrucByIndex = EFI_SMBIOS_ADD_STRUC_INDEX_FUNC;
  mAmiSmbiosProtocol.SmbiosUpdateHeader = EFI_SMBIOS_UPDATE_HEADER_FUNC;
  mAmiSmbiosProtocol.SmbiosGetVerTableEntryPoint = EFI_SMBIOS_GET_VER_TABLE_ENTRY_FUNC;
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &Handle,
                  &gAmiSmbiosProtocolGuid,
                  &mAmiSmbiosProtocol,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);



  mGlobalNvsAreaProtocol.Area = DxeBuffer;
  ASSERT(sizeof(EFI_GLOBAL_NVS_AREA) < 0x50000);
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &Handle,
                  &gEfiGlobalNvsAreaProtocolGuid,
                  &mGlobalNvsAreaProtocol,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);
  
  mSaGlobalNvsAreaProtocol.Area = DxeBuffer;
  ASSERT(sizeof(SYSTEM_AGENT_GLOBAL_NVS_AREA) < 0x50000);
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &Handle,
                  &gSaGlobalNvsAreaProtocolGuid,
                  &mSaGlobalNvsAreaProtocol,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);

  mEfiPlatforminfoProtocol.GetKeyValue = EFI_PLATFORMINFO_GET_KEYVALUE_FUNC;
  mEfiPlatforminfoProtocol.GetPlatformInfo = EFI_PLATFORMINFO_GET_PLATFORMINFO_FUNC;
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &Handle,
                  &gEfiPlatformInfoProtocolGuid,
                  &mEfiPlatforminfoProtocol,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);

  mEfiBootScriptSaveProtocol.Write = EFI_BOOT_SCRIPT_WRITE_FUNC;
  mEfiBootScriptSaveProtocol.CloseTable = EFI_BOOT_SCRIPT_CLOSE_TABLE_FUNC;
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &Handle,
                  &gEfiBootScriptSaveProtocolGuid,
                  &mEfiBootScriptSaveProtocol,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);

  mAmiFlashProtocol.Read =  AMI_FLASH_READ_FUNC;
  mAmiFlashProtocol.Erase =  AMI_FLASH_ERASE_FUNC;
  mAmiFlashProtocol.Write =  AMI_FLASH_WRITE_FUNC;
  mAmiFlashProtocol.Update =  AMI_FLASH_UPDATE_FUNC;
  mAmiFlashProtocol.DeviceWriteEnable =  AMI_FLASH_WRITE_ENABLE_FUNC;
  mAmiFlashProtocol.DeviceWriteDisable =  AMI_FLASH_WRITE_DISABLE_FUNC;
  mAmiFlashProtocol.Reserved1 = DxeBuffer;
  mAmiFlashProtocol.Reserved2 = DxeBuffer;
  mAmiFlashProtocol.Reserved3 = DxeBuffer;
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &Handle,
                  &gAmiFlashProtocolGuid,
                  &mAmiFlashProtocol,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);

  // mEfiSmiFlashProtocol.GetFlashInfo = GET_FLASH_INFO_FUNC;
  // mEfiSmiFlashProtocol.EnableFlashWrite = ENABLE_FLASH_FUNC;
  // mEfiSmiFlashProtocol.DisableFlashWrite = DISABLE_FLASH_FUNC;
  // mEfiSmiFlashProtocol.ReadFlash = READ_FLASH_FUNC;
  // mEfiSmiFlashProtocol.WriteFlash = WRITE_FLASH_FUNC;
  // mEfiSmiFlashProtocol.EraseFlash = ERASE_FLASH_FUNC;
  // Status = gBS->InstallMultipleProtocolInterfaces (
  //                 &Handle,
  //                 &gEfiSmiFlashProtocolGuid,
  //                 &mEfiSmiFlashProtocol,
  //                 NULL
  //                 );
  // ASSERT_EFI_ERROR (Status);
  // Status = gBS->InstallMultipleProtocolInterfaces (
  //                 &Handle,
  //                 &gAmiSmmFlashProtocolGuid,
  //                 &mEfiSmiFlashProtocol,
  //                 NULL
  //                 );
  // ASSERT_EFI_ERROR (Status);

  mEfiHeciProtocol.SendwACK = EFI_HECI_SENDWACK_FUNC;
  mEfiHeciProtocol.ReadMsg = EFI_HECI_READ_MESSAGE_FUNC;
  mEfiHeciProtocol.SendMsg = EFI_HECI_SEND_MESSAGE_FUNC;
  mEfiHeciProtocol.ResetHeci = EFI_HECI_RESET_FUNC;
  mEfiHeciProtocol.InitHeci = EFI_HECI_INIT_FUNC;
  mEfiHeciProtocol.MeResetWait = EFI_HECI_RESET_WAIT_FUNC;
  mEfiHeciProtocol.ReInitHeci = EFI_HECI_REINIT_FUNC;
  mEfiHeciProtocol.GetMeStatus = EFI_HECI_GET_ME_STATUS_FUNC;
  mEfiHeciProtocol.GetMeMode = EFI_HECI_GET_ME_MODE_FUNC;
  mEfiHeciProtocol.ReadAndFlush = EFI_HECI_READ_FLUSH_MESSAGE_FUNC;
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &Handle,
                  &gEfiHeciProtocolGuid,
                  &mEfiHeciProtocol,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);

  mAmiPciExtProtocol.IsPciExpress = AMI_PCI_EXT_IS_PCI_EXPRESS_FUNC;
  mAmiPciExtProtocol.IsPciX = AMI_PCI_EXT_IS_PCI_X_FUNC;
  mAmiPciExtProtocol.IsPci2PciBridge = AMI_PCI_EXT_IS_P2P_BRG_FUNC;
  mAmiPciExtProtocol.IsPci2CrdBridge = AMI_PCI_EXT_IS_CRD_BRG_FUNC;
  mAmiPciExtProtocol.IsPciDevice = AMI_PCI_EXT_IS_REG_DEVICE_FUNC;
  mAmiPciExtProtocol.GetClassCodesInfo = AMI_PCI_EXT_GET_CLASS_CODES_INFO_FUNC;
  mAmiPciExtProtocol.GetPciPicIrq = AMI_PCI_EXT_GET_PCI_PIC_IRQ_FUNC;
  mAmiPciExtProtocol.GetPciApicIrq = AMI_PCI_EXT_GET_PCI_APIC_IRQ_FUNC;
  mAmiPciExtProtocol.PciExtHanle = NULL;
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &Handle,
                  &gAmiExtPciBusProtocolGuid,
                  &mAmiPciExtProtocol,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);

  ASSERT(sizeof(EFI_PCH_INFO_PROTOCOL) < 0x50000);
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &Handle,
                  &gEfiPchInfoProtocolGuid,
                  DxeBuffer,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);

  mEfiIioUdsProtocol.EnableVc = IIH_ENABLE_VC_FUNC;
  mEfiIioUdsProtocol.IioUdsPtr = AllocatePool(sizeof(IIO_UDS));
  ZeroMem(mEfiIioUdsProtocol.IioUdsPtr, sizeof(IIO_UDS));
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &Handle,
                  &gEfiIioUdsProtocolGuid,
                  &mEfiIioUdsProtocol,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);

  
  mEfiWheaSupportProtocol.AddErrorSource = EFI_ADD_ERROR_SOURCE_FUNC;
  mEfiWheaSupportProtocol.AddBootErrorLog = EFI_ADD_BOOT_ERROR_LOG_FUNC;
  mEfiWheaSupportProtocol.InstallErrorInjectionMethod = EFI_INSTALL_ERROR_INJECTION_METHOD_FUNC;
  mEfiWheaSupportProtocol.GetErrorInjectionCapability = EFI_GET_ERROR_INJECTION_CAPABILITY_FUNC;
  mEfiWheaSupportProtocol.GetElar = EFI_GET_ELAR_FUNC;
  mEfiWheaSupportProtocol.InstallErrorRecordMethod = EFI_INSTALL_ERROR_RECORD_METHOD_FUNC;
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &Handle,
                  &gEfiWheaSupportProtocolGuid,
                  &mEfiWheaSupportProtocol,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);

  ASSERT(sizeof(PPM_PLATFORM_POLICY_PROTOCOL) < 0x50000);
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &Handle,
                  &gPpmPlatformPolicyProtocolGuid,
                  DxeBuffer,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);

  mEfiIioSystemProtocol.IioGlobalData = DxeBuffer;
  ASSERT(sizeof(IIO_GLOBALS) < 0x50000);
  mEfiIioSystemProtocol.IioGetCpuUplinkPort = IIO_GET_CPU_UPLINK_PORT_FUNC;
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &Handle,
                  &gEfiIioSystemProtocolGuid,
                  &mEfiIioSystemProtocol,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);

  mEfiUsb2HcProtocol.GetCapability = EFI_USB2_HC_PROTOCOL_GET_CAPABILITY_FUNC;
  mEfiUsb2HcProtocol.Reset = EFI_USB2_HC_PROTOCOL_RESET_FUNC;
  mEfiUsb2HcProtocol.GetState = EFI_USB2_HC_PROTOCOL_GET_STATE_FUNC;
  mEfiUsb2HcProtocol.SetState = EFI_USB2_HC_PROTOCOL_SET_STATE_FUNC;
  mEfiUsb2HcProtocol.ControlTransfer =  EFI_USB2_HC_PROTOCOL_CONTROL_TRANSFER_FUNC;
  mEfiUsb2HcProtocol.BulkTransfer =  EFI_USB2_HC_PROTOCOL_BULK_TRANSFER_FUNC;
  mEfiUsb2HcProtocol.AsyncInterruptTransfer =  EFI_USB2_HC_PROTOCOL_ASYNC_INTERRUPT_TRANSFER_FUNC;
  mEfiUsb2HcProtocol.SyncInterruptTransfer = EFI_USB2_HC_PROTOCOL_SYNC_INTERRUPT_TRANSFER_FUNC;
  mEfiUsb2HcProtocol.IsochronousTransfer = EFI_USB2_HC_PROTOCOL_ISOCHRONOUS_TRANSFER_FUNC;
  mEfiUsb2HcProtocol.AsyncIsochronousTransfer = EFI_USB2_HC_PROTOCOL_ASYNC_ISOCHRONOUS_TRANSFER_FUNC;
  mEfiUsb2HcProtocol.GetRootHubPortStatus =  EFI_USB2_HC_PROTOCOL_GET_ROOTHUB_PORT_STATUS_FUNC;
  mEfiUsb2HcProtocol.ClearRootHubPortFeature =  EFI_USB2_HC_PROTOCOL_CLEAR_ROOTHUB_PORT_FEATURE_FUNC;
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &Handle,
                  &gEfiUsb2HcProtocolGuid,
                  &mEfiUsb2HcProtocol,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);

  mAmiTcgPlatformProtocol.MeasureCpuMicroCode = MEASURE_CPU_MICROCODE_FUNC;
  mAmiTcgPlatformProtocol.MeasurePCIOproms = MEASURE_PCI_OPROMS_FUNC;
  mAmiTcgPlatformProtocol.ProcessTcgSetup = PROCESS_TCG_SETUP_FUNC;
  mAmiTcgPlatformProtocol.ProcessTcgPpiRequest = PROCESS_TCG_PPI_REQUEST_FUNC;
  mAmiTcgPlatformProtocol.SetTcgReadyToBoot = TCG_READY_TO_BOOT_FUNC;
  mAmiTcgPlatformProtocol.GetProtocolVersion = GET_PROTOCOL_VERSION_FUNC;
  mAmiTcgPlatformProtocol.ResetOSTcgVar = RESETOSTCGVAR_FUNC;
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &Handle,
                  &gAmiTcgPlatformProtocolguid,
                  &mAmiTcgPlatformProtocol,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);

  mEfiNbErrorLogDispatchProtocol.Register = EFI_NB_ERROR_LOG_REGISTER_FUNC;
  mEfiNbErrorLogDispatchProtocol.UnRegister = EFI_NB_ERROR_LOG_UNREGISTER_FUNC;
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &Handle,
                  &gNbErrorLogDispatchProtocolGuid,
                  &mEfiNbErrorLogDispatchProtocol,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);

  ASSERT(sizeof(MEM_INFO_PROTOCOL) < 0x50000);
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &Handle,
                  &gMemInfoProtocolGuid,
                  DxeBuffer,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);

  ZeroMem(&mDxeCpuPlatformPolicyProtocol,sizeof(DXE_CPU_PLATFORM_POLICY_PROTOCOL));
  mDxeCpuPlatformPolicyProtocol.CpuConfig = AllocatePool(sizeof(CPU_CONFIG));
  ZeroMem(mDxeCpuPlatformPolicyProtocol.CpuConfig, sizeof(CPU_CONFIG));
  mDxeCpuPlatformPolicyProtocol.CpuConfig->RetrieveMicrocode = PLATFORM_CPU_RETRIEVE_MICROCODE_FUNC;
  mDxeCpuPlatformPolicyProtocol.CpuConfig->GetMaxCount = PLATFORM_CPU_GET_MAX_COUNT_FUNC;
  mDxeCpuPlatformPolicyProtocol.CpuConfig->GetCpuInfo = PLATFORM_CPU_GET_CPU_INFO_FUNC;
  mDxeCpuPlatformPolicyProtocol.PowerMgmtConfig = AllocatePool(sizeof(POWER_MGMT_CONFIG));
  ZeroMem(mDxeCpuPlatformPolicyProtocol.PowerMgmtConfig, sizeof(POWER_MGMT_CONFIG));
  mDxeCpuPlatformPolicyProtocol.PowerMgmtConfig->pFunctionEnables = AllocatePool(sizeof(PPM_FUNCTION_ENABLES));
  ZeroMem(mDxeCpuPlatformPolicyProtocol.PowerMgmtConfig->pFunctionEnables, sizeof(PPM_FUNCTION_ENABLES));
  mDxeCpuPlatformPolicyProtocol.PowerMgmtConfig->pCustomRatioTable = AllocatePool(sizeof(PPM_CUSTOM_RATIO_TABLE));
  ZeroMem(mDxeCpuPlatformPolicyProtocol.PowerMgmtConfig->pCustomRatioTable, sizeof(PPM_CUSTOM_RATIO_TABLE));
  mDxeCpuPlatformPolicyProtocol.PowerMgmtConfig->pTurboSettings = AllocatePool(sizeof(PPM_TURBO_SETTINGS));
  ZeroMem(mDxeCpuPlatformPolicyProtocol.PowerMgmtConfig->pTurboSettings, sizeof(PPM_TURBO_SETTINGS));
  mDxeCpuPlatformPolicyProtocol.PowerMgmtConfig->pRatioLimit = AllocatePool(sizeof(UINT8));
  ZeroMem(mDxeCpuPlatformPolicyProtocol.PowerMgmtConfig->pRatioLimit, sizeof(UINT8));
  mDxeCpuPlatformPolicyProtocol.PowerMgmtConfig->pPpmLockEnables = AllocatePool(sizeof(PPM_LOCK_ENABLES));
  ZeroMem(mDxeCpuPlatformPolicyProtocol.PowerMgmtConfig->pPpmLockEnables, sizeof(PPM_LOCK_ENABLES));
  mDxeCpuPlatformPolicyProtocol.PowerMgmtConfig->pCustomCtdpSettings = AllocatePool(sizeof(PPM_CUSTOM_CTDP));
  ZeroMem(mDxeCpuPlatformPolicyProtocol.PowerMgmtConfig->pCustomCtdpSettings, sizeof(PPM_CUSTOM_CTDP));
  mDxeCpuPlatformPolicyProtocol.PowerMgmtConfig->ThermalFuncEnables = AllocatePool(sizeof(THERM_FUNCTION_ENABLES));
  ZeroMem(mDxeCpuPlatformPolicyProtocol.PowerMgmtConfig->ThermalFuncEnables, sizeof(THERM_FUNCTION_ENABLES));
  mDxeCpuPlatformPolicyProtocol.SecurityConfig = AllocatePool(sizeof(SECURITY_CONFIG));
  mDxeCpuPlatformPolicyProtocol.SecurityConfig->TxtFunctionConfig = AllocatePool(sizeof(TXT_FUNCTION_CONFIG));
  ZeroMem(mDxeCpuPlatformPolicyProtocol.SecurityConfig->TxtFunctionConfig, sizeof(TXT_FUNCTION_CONFIG));
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &Handle,
                  &gDxeCpuPlatformPolicyProtocolGuid,
                  &mDxeCpuPlatformPolicyProtocol,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);

  mEfiAlertStandardFormatProtocol.GetSmbusAddr = EFI_ALERT_STANDARD_FORMAT_PROTOCOL_GET_SMBUSADDR_FUNC;
  mEfiAlertStandardFormatProtocol.SetSmbusAddr = EFI_ALERT_STANDARD_FORMAT_PROTOCOL_SET_SMBUSADDR_FUNC;
  mEfiAlertStandardFormatProtocol.GetBootOptions = EFI_ALERT_STANDARD_FORMAT_PROTOCOL_GET_BOOT_OPTIONS_FUNC;
  mEfiAlertStandardFormatProtocol.SendAsfMessage = EFI_ALERT_STANDARD_FORMAT_PROTOCOL_SEND_ASF_MESSAGE_FUNC;
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &Handle,
                  &gEfiAlertStandardFormatProtocolGuid,
                  &mEfiAlertStandardFormatProtocol,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);

  ASSERT(sizeof(DXE_PCH_PLATFORM_POLICY_PROTOCOL) < 0x50000);
  ZeroMem(&mDxePchPlatformPolicyProtocol, sizeof(DXE_PCH_PLATFORM_POLICY_PROTOCOL));
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &Handle,
                  &gDxePchPlatformPolicyProtocolGuid,
                  DxeBuffer,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);

  mEfiTcgProtocol.HashAll = EFI_TCG_HASH_ALL_FUNC;
  mEfiTcgProtocol.HashLogExtendEvent = EFI_TCG_HASH_LOG_EXTEND_EVENT_FUNC;
  mEfiTcgProtocol.LogEvent = EFI_TCG_LOG_EVENT_FUNC;
  mEfiTcgProtocol.PassThroughToTpm = EFI_TCG_PASS_THROUGH_TO_TPM_FUNC;
  mEfiTcgProtocol.StatusCheck = EFI_TCG_STATUS_CHECK_FUNC;
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &Handle,
                  &gEfiTcgProtocolGuid,
                  &mEfiTcgProtocol,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);

  mEfiTreeProtocol.GetCapability = EFI_TREE_GET_CAPABILITY_FUNC;
  mEfiTreeProtocol.GetEventLog = EFI_TREE_GET_EVENT_LOG_FUNC;
  mEfiTreeProtocol.HashLogExtendEvent = EFI_TREE_HASH_LOG_EXTEND_EVENT_FUNC;
  mEfiTreeProtocol.SubmitCommand = EFI_TREE_SUBMIT_COMMAND_FUNC;
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &Handle,
                  &gEfiTrEEProtocolGuid,
                  &mEfiTreeProtocol,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);


  nEfiUsbProtocol.USBDataPtr = AllocatePool(0x50000);
  Status = gBS->InstallMultipleProtocolInterfaces (
                &Handle,
                &gEfiUsbProtocolGuid,
                &nEfiUsbProtocol,
                NULL
                );
  ASSERT_EFI_ERROR (Status);

  mEfiSmbusHcProtocol.ArpDevice = EFI_SMBUS_HC_PROTOCOL_ARP_DEVICE_FUNC;
  mEfiSmbusHcProtocol.Execute = EFI_SMBUS_HC_EXECUTE_OPERATION_FUNC;
  mEfiSmbusHcProtocol.GetArpMap = EFI_SMBUS_HC_PROTOCOL_GET_ARP_MAP_FUNC;
  mEfiSmbusHcProtocol.Notify = EFI_SMBUS_HC_PROTOCOL_NOTIFY_FUNC;
  Status = gBS->InstallMultipleProtocolInterfaces (
    &Handle,
    &gEfiSmbusHcProtocolGuid,
    &mEfiSmbusHcProtocol,
    NULL
  );
  ASSERT_EFI_ERROR (Status);

  VOID* Tmp = AllocatePool(0x50000);
  Status = gBS->InstallMultipleProtocolInterfaces (
    &Handle,
    &gEfiSystemUsbSupportPolicyProtocol,
    Tmp,
    NULL
  );
  ASSERT_EFI_ERROR (Status);
  
  static GUID UnknownSmmFuzzProtocols[] = {
    { 0x5B4CB5FD, 0x42F4, 0x27A0, { 0xCC, 0xEB, 0xD9, 0xA2, 0x8E, 0x6B, 0x91, 0xFC } },
    { 0x01A55897, 0xF83D, 0x43AA, { 0xA4, 0x38, 0x81, 0x62, 0x18, 0xB8, 0xAF, 0xB5 } },
    { 0x443CDE79, 0xA599, 0x4CB7, { 0xB0, 0x4B, 0x73, 0x7F, 0x9E, 0x63, 0x06, 0xFB } },
    { 0xA073A3A6, 0x96EC, 0x4173, { 0xA9, 0xBC, 0x39, 0x95, 0x06, 0xCD, 0xEA, 0xC6 } },
    { 0x4D6A54D1, 0xCD56, 0x47F3, { 0x93, 0x6E, 0x7E, 0x51, 0xD9, 0x31, 0x15, 0x4F } },
    { 0x7AA096A6, 0xC4AF, 0x49AF, { 0xAD, 0xDD, 0x98, 0x9F, 0x1C, 0x55, 0x76, 0x4A } },
    { 0xE4EB9F35, 0xE1DF, 0x45D1, { 0x97, 0x2B, 0xEB, 0xA4, 0xE6, 0x5E, 0xD5, 0x44 } },
    { 0x5E5A2DAD, 0x6EF7, 0x4210, { 0xB7, 0x61, 0x95, 0x8E, 0x83, 0xDC, 0xDF, 0x79 } },
    { 0xACE5A4FB, 0x874B, 0x42CB, { 0x9B, 0xCA, 0xC2, 0x2E, 0xEB, 0x12, 0x2E, 0x01 } },
    { 0x8A51C4CC, 0xF3BA, 0x4895, { 0xB0, 0xE2, 0x90, 0xE4, 0xA6, 0x1A, 0x91, 0xC7 } },
    { 0x579CB2CB, 0x3403, 0x4B26, { 0x84, 0xCD, 0x72, 0x89, 0xFC, 0x91, 0x4D, 0x35 } },
    { 0x9A19EF65, 0x0E00, 0x44CA, { 0xB6, 0xF2, 0x04, 0xA2, 0xCB, 0x59, 0xF7, 0xE1 } },
    { 0xD3132591, 0xB110, 0x41C4, { 0x9A, 0x2D, 0x89, 0x33, 0xA0, 0xC2, 0x5C, 0x9F } },
    { 0xB0E7F06E, 0x867A, 0x4FBF, { 0xBD, 0xD0, 0x91, 0xA7, 0x6E, 0xD9, 0x2F, 0x91 } },
    { 0x736102F1, 0x9584, 0x44E7, { 0x82, 0x8A, 0x43, 0x4B, 0x1E, 0x67, 0x5C, 0xC4 } },
    { 0xB34B83D9, 0x41FA, 0x84D4, { 0x7B, 0xE9, 0xD2, 0x88, 0x5B, 0x49, 0xDF, 0x95 } },
    { 0x154774EC, 0x4350, 0x40D4, { 0xAF, 0x66, 0x7D, 0x18, 0x37, 0xBC, 0xD5, 0x59 } },
    { 0xAB63700F, 0x7DEE, 0x49E0, { 0x8C, 0xDB, 0xF4, 0xA0, 0xAA, 0x99, 0x53, 0x23 } },
    { 0x3328028A, 0x9D48, 0x489C, { 0xB7, 0x3F, 0xF2, 0xB3, 0x20, 0x42, 0x30, 0xC1 } },
    { 0xBD5C43F3, 0x7BEB, 0x4764, { 0x85, 0x5C, 0x22, 0xA1, 0xD7, 0x93, 0xAD, 0xEC } },
    { 0x343010C7, 0x4608, 0x44C8, { 0x80, 0x97, 0x04, 0xC4, 0x00, 0xF4, 0x0A, 0x93 } },
    { 0x90D4ECA9, 0x8E31, 0x4604, { 0xA0, 0x4D, 0x19, 0xF8, 0xB1, 0x2D, 0x12, 0xCC } },
    { 0x3C7BFA67, 0x4F7D, 0x6E3D, { 0x5B, 0x34, 0x52, 0x93, 0xEB, 0x51, 0xAE, 0xB0 } },
    { 0xF932C266, 0x75CA, 0x4D1F, { 0x90, 0x16, 0x42, 0x3F, 0x10, 0x3D, 0x82, 0x53 } },
    { 0x784F0BDA, 0xF028, 0x4B89, { 0x9C, 0x04, 0x1D, 0x17, 0x84, 0x82, 0x4D, 0xAE } },
    { 0x4010D299, 0xDFA3, 0x42CA, { 0xAE, 0x1D, 0x7A, 0x59, 0xD3, 0x4D, 0x94, 0x70 } },
    { 0x2E78BFC4, 0x4C4A, 0x8350, { 0x50, 0xB1, 0x8D, 0x84, 0x6F, 0x70, 0x0E, 0xA3 } },
    { 0xE6F014AB, 0xCB0E, 0x456E, { 0x8A, 0xF7, 0x72, 0x21, 0xED, 0xB7, 0x02, 0xF7 } },
    { 0xF447D1DD, 0x1205, 0x4AC2, { 0xBA, 0x53, 0xB7, 0xD6, 0x5A, 0x31, 0xD3, 0x12 } },
    { 0x0E5870E4, 0x0525, 0x40AD, { 0x95, 0xA8, 0x0F, 0xFF, 0x15, 0x5B, 0x8F, 0xC0 } },
    { 0x55EC2F53, 0x5ABC, 0x4D9F, { 0xBB, 0x02, 0xE1, 0xE7, 0x12, 0x61, 0x38, 0x96 } },
    { 0x881B4AB6, 0x17B0, 0x4BDF, { 0x88, 0xE2, 0xD4, 0x29, 0xDA, 0x42, 0x5F, 0xFD } },
    { 0xD7BF10F3, 0xF98C, 0x4C81, { 0xA4, 0xAD, 0x08, 0xAD, 0xEA, 0xC4, 0xD9, 0x71 } },
    { 0x2F08BAC6, 0x8D86, 0x483A, { 0xB5, 0x28, 0x7E, 0x4B, 0x47, 0x00, 0x24, 0x8C } },
    { 0x3C6ED57C, 0x4F6A, 0x8A58, { 0x85, 0xDF, 0xDC, 0xA5, 0xAD, 0xF0, 0xF1, 0x6B } },
    { 0xC63C0C73, 0xF612, 0x4C02, { 0x84, 0xA3, 0xC6, 0x40, 0xAD, 0x0B, 0x12, 0x34 } },
    { 0xD8C0BEB0, 0xC23B, 0x4624, { 0xAA, 0xF3, 0xCA, 0xF3, 0x0B, 0x5D, 0xB3, 0x56 } },
    { 0x92299EAF, 0x6692, 0x485D, { 0xAE, 0x2C, 0xCD, 0x07, 0x78, 0x97, 0x40, 0x8B } },
    { 0xA6E0C601, 0x46EB, 0x4A83, { 0xAC, 0xE3, 0x14, 0xDA, 0x30, 0x1F, 0x5A, 0x85 } },
    { 0x4E703E0C, 0xD4B5, 0x4923, { 0xA9, 0x96, 0xD1, 0x35, 0x9D, 0x1D, 0x4C, 0x68 } },
    { 0xE025746C, 0xD483, 0x498C, { 0xB7, 0x17, 0xE2, 0xFF, 0x99, 0x98, 0x4F, 0x9B } },
    { 0x3EF7500E, 0xCF55, 0x474F, { 0x8E, 0x7E, 0x00, 0x9E, 0x0E, 0xAC, 0xEC, 0xD2 } },
    { 0x1224B1B9, 0xCBA1, 0x41CA, { 0x82, 0xA7, 0xDC, 0xF5, 0xEE, 0x6A, 0xEB, 0xED } },
    { 0xE541B773, 0xDD11, 0x420C, { 0xB0, 0x26, 0xDF, 0x99, 0x36, 0x53, 0xF8, 0xBF } },
    { 0x25358F8B, 0xC684, 0x4F7C, { 0x80, 0x4B, 0xA8, 0x13, 0xEE, 0xB8, 0xC5, 0xEE } },
    { 0xDB4A79AC, 0x5BBB, 0x4625, { 0xA6, 0x9E, 0xFE, 0xBF, 0x9D, 0x6D, 0x12, 0x34 } },
    { 0xF5DD1F71, 0xC3E2, 0x473D, { 0x84, 0xD5, 0x34, 0x1A, 0x37, 0x40, 0x54, 0xAF } },
    { 0x53986F2E, 0x4F54, 0x4D40, { 0x81, 0x66, 0x0E, 0x02, 0x0F, 0xBA, 0xBF, 0xBC } },
    { 0xD4B64FCA, 0x7C4C, 0x48C1, { 0x97, 0x6F, 0x52, 0x87, 0x42, 0x37, 0x53, 0xE4 } },
    { 0x1390954D, 0xDA95, 0x4227, { 0x93, 0x28, 0x72, 0x82, 0xC2, 0x17, 0xDA, 0xA8 } },
    { 0xE3FA08C8, 0x4474, 0x4FFF, { 0x8A, 0xB9, 0xE9, 0xA7, 0x0D, 0x98, 0x06, 0xC0 } },
    { 0x58D75B48, 0x5D7F, 0x4A21, { 0xA8, 0x53, 0xE0, 0x1A, 0xD7, 0xA5, 0x18, 0xA7 } },
    { 0x1C4C501A, 0x8CDC, 0x4D1F, { 0x86, 0x39, 0x27, 0xE9, 0x04, 0x94, 0x94, 0xC1 } },
    { 0xB50A6A58, 0x5359, 0x4E79, { 0xB5, 0x9D, 0x20, 0x42, 0x1C, 0xF6, 0x37, 0x47 } },
    { 0xF8B1B592, 0x4D8A, 0xDE8F, { 0x61, 0x62, 0xC8, 0x86, 0xE9, 0x98, 0x6C, 0x27 } },
    { 0xCABF469A, 0x4E65, 0x34FC, { 0x5B, 0x48, 0xFB, 0xBD, 0x99, 0x3C, 0x68, 0x1E } },
    { 0xB8167809, 0xE73A, 0x4387, { 0x83, 0x23, 0x0A, 0xFE, 0x83, 0xD3, 0x07, 0x4F } },
    { 0x544FA3A0, 0x47E0, 0x48F9, { 0x8B, 0x70, 0xCC, 0x52, 0x73, 0x88, 0xDC, 0x17 } },
    { 0x0FE9A1F0, 0x1472, 0x44E4, { 0xAD, 0x65, 0x9B, 0x27, 0xC3, 0x7B, 0x17, 0xBF } },
    { 0x543D5C93, 0x6A28, 0x4513, { 0x85, 0x9A, 0x82, 0xA7, 0xB9, 0x12, 0xCB, 0xBE } },
    { 0x4FB18DED, 0xD0F9, 0x4B9E, { 0xBF, 0x2B, 0x32, 0x35, 0xCF, 0xBD, 0x80, 0xBA } },
    { 0xD5B81429, 0xB0BF, 0x42D9, { 0x90, 0x93, 0x35, 0x79, 0x87, 0xFD, 0x5B, 0xD7 } },
    { 0xEB8F7C39, 0x15BC, 0x454A, { 0x8E, 0x83, 0x77, 0x5D, 0x33, 0xCB, 0x69, 0xC4 } },
    { 0xF1B3A996, 0x612E, 0x443D, { 0xA9, 0x85, 0xB4, 0x70, 0x0E, 0x57, 0xE4, 0xF2 } },
    { 0x5CB5C776, 0x60D5, 0x45EE, { 0x88, 0x3C, 0x45, 0x27, 0x08, 0xCD, 0x74, 0x3F } },
    { 0xA365240E, 0x56B0, 0x426D, { 0x83, 0x0A, 0x30, 0x66, 0xC6, 0x81, 0xBE, 0x9A } },
    { 0xCBEB63D0, 0x76E3, 0x11E0, { 0xA1, 0xF0, 0x08, 0x00, 0x20, 0x0C, 0x9A, 0x66 } },
    { 0xB356A1DE, 0x4FCB, 0x4EC1, { 0x91, 0x7C, 0x10, 0xA3, 0xCF, 0x05, 0xC0, 0x91 } },
    { 0x3724CF01, 0x00C2, 0x9762, { 0x11, 0xB3, 0x0E, 0xA8, 0xAA, 0x89, 0x72, 0x00 } },
    { 0x6FDD7947, 0x6945, 0x4349, { 0xA4, 0x09, 0xCB, 0x79, 0xD3, 0xFD, 0xDE, 0x00 } },
    { 0x41821FFF, 0x8B93, 0x4E4E, { 0xA7, 0x5B, 0x85, 0x0D, 0x49, 0x46, 0x1A, 0x33 } },
    { 0x13BD659B, 0xB4C6, 0x47DA, { 0x9B, 0x22, 0x11, 0x50, 0xD4, 0xF3, 0x0B, 0xDA } },
    { 0xD3D7C640, 0x1782, 0x475E, { 0x8E, 0x7B, 0x52, 0xDF, 0x4A, 0xE9, 0x03, 0xFA } },
    { 0x7576CC89, 0x8FA3, 0x4CAD, { 0xBA, 0x02, 0x61, 0x19, 0xB4, 0x6E, 0xD4, 0x4A } },
    { 0x348A2594, 0x43E1, 0x418A, { 0xA5, 0x14, 0xCC, 0xB6, 0xE8, 0x46, 0x5A, 0x5C } },
    { 0xDCEF1B52, 0x2605, 0x4735, { 0x8F, 0x91, 0x04, 0x9D, 0x6D, 0xE7, 0x59, 0xDF } },
    { 0xE8FE82E8, 0x7D00, 0x41FF, { 0x91, 0x1E, 0x0B, 0x99, 0x6F, 0x85, 0xC9, 0x57 } },
    { 0x6C5AE0F9, 0xAAD3, 0x47F8, { 0x8F, 0x59, 0xA5, 0x3A, 0x54, 0xCE, 0x5A, 0xE2 } },
    { 0x2DF1E051, 0x906D, 0x4EFF, { 0x86, 0x9D, 0x24, 0xE6, 0x53, 0x78, 0xFB, 0x9E } },
    { 0x4FC43BBE, 0x1433, 0x4951, { 0xAC, 0x2D, 0x0D, 0x01, 0xFE, 0xC0, 0x0E, 0xB1 } },
    { 0xA8AD1743, 0xC841, 0x4DBF, { 0xB6, 0x51, 0xAE, 0x75, 0xC6, 0xB1, 0x19, 0x23 } },
    { 0xDB4A79AC, 0x5BBB, 0x4625, { 0xA6, 0x9E, 0xFE, 0xBF, 0x9D, 0x6D, 0x95, 0xEB } },
    { 0x4B844201, 0x6FE9, 0x41D1, { 0xB4, 0x6F, 0xDF, 0xFC, 0x34, 0xE4, 0x92, 0xA2 } },
    { 0xA0B5DC52, 0x4F34, 0x3990, { 0xD4, 0x91, 0x10, 0x8B, 0xE8, 0xBA, 0x75, 0x42 } },
    { 0x2C74511B, 0x4D15, 0x4190, { 0x89, 0xFE, 0x7D, 0x45, 0xBB, 0x31, 0x6D, 0x6C } },
    { 0x96C5A344, 0x966A, 0x469A, { 0x99, 0xB8, 0xC8, 0x64, 0x44, 0xA9, 0x95, 0x51 } },
    { 0xCEA5FC27, 0x5183, 0x4899, { 0xA6, 0x4E, 0x7B, 0x87, 0x49, 0xC9, 0x62, 0xE2 } },
    { 0x6FCE3BB9, 0x9742, 0x4CFD, { 0x8E, 0x9E, 0x39, 0xF9, 0x8D, 0xCA, 0x32, 0x71 } },
    { 0x33381F15, 0x15ED, 0x467A, { 0xA6, 0xC9, 0xCC, 0x1B, 0x86, 0xCA, 0xD8, 0xD8 } },
    { 0x53AF9368, 0xB844, 0x455B, { 0xAE, 0x8A, 0x15, 0xDB, 0x11, 0xE1, 0x8F, 0x20 } },
    { 0x380D7A5E, 0x1BCA, 0x11E1, { 0xA1, 0x10, 0xE8, 0xEB, 0x47, 0x24, 0x01, 0x9B } },
    { 0x49240652, 0x0D81, 0x445D, { 0xAE, 0x1B, 0x51, 0xEC, 0x24, 0xF8, 0xD0, 0x07 } },
    { 0x3BF4AF16, 0xAB7C, 0x4B43, { 0x89, 0x8D, 0xAB, 0x26, 0xAC, 0x5D, 0xDC, 0x6C } },
    { 0x52FC9EA1, 0xB67F, 0x4A8A, { 0x93, 0x87, 0xF2, 0x48, 0xA9, 0xA7, 0x01, 0xA1 } },
    { 0xCA3B07C1, 0x4FEE, 0x49F4, { 0xA2, 0xC1, 0xE8, 0xC0, 0x89, 0xB9, 0x4A, 0xEE } },
    { 0xEE63CE96, 0xB809, 0x41D5, { 0xAB, 0x97, 0xFC, 0x97, 0x8D, 0xA5, 0x26, 0xF0 } },
    { 0x196BF9E3, 0x20D7, 0x4B7B, { 0x89, 0xF9, 0x31, 0xC2, 0x72, 0x08, 0xC9, 0xB9 } },
    { 0x4B5C6807, 0xB65B, 0x4E0A, { 0x82, 0x9A, 0xE2, 0xAB, 0x9B, 0x84, 0x98, 0xF0 } },
    { 0x3C73D7B0, 0x3FA3, 0x42A3, { 0xB0, 0xCB, 0xC1, 0xB0, 0x93, 0x3C, 0x64, 0x75 } },
    { 0x84310C9D, 0x82BF, 0x44C1, { 0x8B, 0xC5, 0x29, 0x9B, 0x74, 0x01, 0xEA, 0xAC } },
    { 0x8151730C, 0xE1D3, 0x4C8C, { 0x91, 0x7B, 0xA3, 0x9B, 0x7E, 0xD4, 0x82, 0x65 } },
    { 0xF281FC6E, 0xF4C4, 0x431C, { 0x96, 0x2B, 0x2F, 0x13, 0xAE, 0x79, 0x84, 0xEC } },
    { 0xD4D2F201, 0x50E8, 0x4D45, { 0x8E, 0x05, 0xFD, 0x49, 0xA8, 0x2A, 0x15, 0x69 } },
    { 0x4E853A1E, 0xCAD3, 0x437C, { 0x9F, 0xE1, 0x5A, 0x05, 0x88, 0x88, 0xFF, 0xB1 } },
    { 0xDAE670DB, 0x2C65, 0x41E9, { 0xBD, 0xF8, 0x06, 0x3C, 0x80, 0x02, 0xDE, 0x0A } },
    { 0x9B48BE80, 0x57BE, 0x47D3, { 0xB2, 0x51, 0x00, 0xDF, 0x2C, 0xAC, 0xBB, 0xB1 } },
    { 0x4B5C6808, 0xB65B, 0x4E0A, { 0x82, 0x9A, 0xE2, 0xAB, 0x9B, 0x84, 0x98, 0xF0 } },
    { 0x19DBF79A, 0x3A95, 0x4758, { 0x81, 0x69, 0x86, 0x9A, 0xE2, 0x7F, 0x38, 0x17 } },
    { 0xABBF33F9, 0x3581, 0x44A2, { 0x8D, 0x66, 0x8C, 0x9E, 0x14, 0xC7, 0xA6, 0x56 } },
    { 0xC35F9520, 0x5791, 0x4667, { 0xAD, 0xE4, 0x1C, 0xFD, 0xA8, 0x37, 0x72, 0x2D } },
    { 0x91288FC4, 0xE64B, 0x4EF9, { 0xA4, 0x63, 0x66, 0x88, 0x00, 0x71, 0x7F, 0xCA } },
    { 0x7051AB6D, 0x9EC2, 0x42EB, { 0xA2, 0x13, 0xDE, 0x48, 0x81, 0xF1, 0xF7, 0x87 } },
    { 0xDB4A79AC, 0x5BBB, 0x4625, { 0x6A, 0x9E, 0xFE, 0xBF, 0x9D, 0x6D, 0x95, 0xEB } },
    { 0x222E7E3A, 0x7D6B, 0x4D70, { 0xB6, 0xB7, 0x3F, 0x05, 0x81, 0xED, 0x95, 0x35 } },
    { 0xC7E8CF4D, 0xFE0C, 0x4EBD, { 0xBE, 0xD5, 0x41, 0x96, 0x49, 0x24, 0xC2, 0xC9 } },
    { 0xE8E07CCF, 0x6CD6, 0x4238, { 0x89, 0x2D, 0xFB, 0x20, 0xF2, 0x7F, 0xBB, 0xA3 } },
    { 0xD3672680, 0xBBCA, 0x4EF6, { 0xBC, 0x8E, 0x70, 0x4A, 0xBC, 0x0C, 0xA8, 0xB5 } },
    { 0x87E2A6CF, 0x91FB, 0x4581, { 0x90, 0xA9, 0x6F, 0x50, 0x5D, 0xDC, 0x1C, 0xB2 } },
    { 0xAB776607, 0x6169, 0x44E8, { 0xB8, 0xF1, 0x50, 0x12, 0x9D, 0x4A, 0x25, 0xDB } },
    { 0x2694A56F, 0xEF32, 0x4EAE, { 0x8B, 0x3F, 0xD3, 0x9B, 0xCA, 0x54, 0x60, 0x21 } },
    { 0x40DAC788, 0xA638, 0x428B, { 0x8D, 0x33, 0x6F, 0x1B, 0xB6, 0xE6, 0xA6, 0x9E } },
    { 0x16D11030, 0x71BA, 0x4E5E, { 0xA9, 0xF9, 0xB4, 0x75, 0xA5, 0x49, 0x04, 0x8A } },
    { 0x956A4D54, 0xFAAB, 0x4916, { 0xAC, 0x99, 0x3D, 0x5D, 0x9A, 0xD0, 0xD7, 0xC0 } },
    { 0x3D6A1546, 0x80E9, 0x46FD, { 0xA7, 0xCA, 0xCC, 0xDF, 0x1F, 0xA6, 0x32, 0xC0 } },
    { 0xF38D7873, 0x987B, 0x4A50, { 0x8E, 0xA2, 0x39, 0xBC, 0x08, 0x03, 0x8C, 0xCA } },
    { 0xD7F78DFE, 0x17A5, 0x4653, { 0xA7, 0x9D, 0x04, 0x98, 0x1F, 0xDA, 0x92, 0x2A } },
    { 0xD0E53AB5, 0x34BB, 0x4BC5, { 0xB3, 0xBC, 0x17, 0x68, 0x15, 0x13, 0xC1, 0x47 } },
    { 0x45066A3B, 0xB760, 0x4411, { 0xA4, 0x20, 0x51, 0x19, 0x21, 0xEF, 0x59, 0x56 } },
    { 0x13D37DF1, 0x017E, 0x4B16, { 0xBD, 0xA8, 0xA3, 0xA4, 0x4D, 0xF8, 0x7C, 0xA4 } },
    { 0x99D3244E, 0xD31A, 0x4839, { 0xA5, 0x39, 0x78, 0x95, 0x4D, 0x2F, 0x8E, 0x61 } },
    { 0x2578EB69, 0x8D1E, 0x435B, { 0xB6, 0xAD, 0x1B, 0x3E, 0xC3, 0x43, 0x6B, 0xEF } },
    { 0xFA8351F0, 0x10DC, 0x46FB, { 0x9C, 0x8E, 0xDC, 0xA4, 0xE2, 0x88, 0x57, 0xA6 } },
    { 0x456D3AC5, 0xCAF0, 0x4E4A, { 0xA0, 0x6C, 0x9E, 0xBE, 0x60, 0xD3, 0xC5, 0xF1 } },
    { 0x8264AAEC, 0x6751, 0x4826, { 0x83, 0xCD, 0x5C, 0x21, 0x87, 0xA4, 0x7A, 0x2E } },
    { 0x57C445F5, 0x48AC, 0x4A50, { 0x9B, 0xB7, 0x08, 0x43, 0xEE, 0x9F, 0x64, 0xAA } },
    { 0x5A034ACB, 0xC575, 0x4BD0, { 0xA5, 0xFF, 0x2B, 0xA9 ,0x00, 0x65, 0xAF, 0xF9 } },
    { 0x4EB9400B, 0x8B89, 0x4C3A, { 0xB5, 0x4E, 0xE0, 0xCF, 0x24, 0x7A, 0x5C, 0xC3 } },
    { 0x4CC17FDE, 0x998A, 0x42F2, { 0x9F, 0x60, 0x36, 0x64, 0xCD, 0x4C, 0x2E, 0xC6 } },
    { 0x333D2F11, 0xC715, 0x4D32, { 0x8B, 0x52, 0xDD, 0x87, 0xC3, 0x03, 0x81, 0x43 } },
    { 0x0B7646A4, 0x6B44, 0x4332, { 0x85, 0x88, 0xC8, 0x99, 0x81, 0x17, 0xF2, 0xEF } },
    { 0xDA297CE4, 0x4863, 0x4912, { 0x81, 0x7F, 0x51, 0x53, 0x81, 0xE3, 0x8C, 0xFE } },
    { 0xBFD02359, 0x8DFE, 0x459A, { 0x8B, 0x69, 0xA7, 0x3A, 0x6B, 0xAF, 0xAD, 0xC0 } }, 
    { 0x30cfe3e7, 0x3de1, 0x4586, { 0xbe, 0x20, 0xde, 0xab, 0xa1, 0xb3, 0xb7, 0x93 } },
    { 0x149A10A5, 0x9D06, 0x4C6B, { 0xBE, 0x44, 0x08, 0x92, 0xCE, 0x20, 0x61, 0xAC } },
    { 0xCAA5CD1F, 0x0DFD, 0x4111, { 0xBA, 0x76, 0x31, 0x8C, 0x28, 0x11, 0x00, 0xB1 } },
    { 0x92AABF22, 0x4AAB, 0x4B01, { 0x99, 0xF0, 0xE4, 0x67, 0xDE, 0xD5, 0xB4, 0x36 } },
    { 0x98314363, 0x42A6, 0x475F, { 0x96, 0x5C, 0x76, 0x50, 0xE4, 0xD5, 0x99, 0x81 } },
    { 0xC75B6C40, 0x0508, 0x4D6C, { 0xB0, 0xBE, 0x18, 0x07, 0x2C, 0xFD, 0x02, 0x9D } },
    { 0x1FA493A8, 0xB360, 0x4205, { 0xB8, 0xFE, 0xCC, 0x83, 0xBC, 0x57, 0xB7, 0x3A } },
    { 0x46632A76, 0xFAB0, 0x4BED, { 0x8F, 0x4A, 0xA9, 0xCA, 0x0B, 0x5E, 0xA9, 0x68 } },
    { 0xAC424D9D, 0x449A, 0x4CBE, { 0x8D, 0x21, 0x66, 0x3A, 0xE3, 0xFD, 0x2E, 0x73 } },
    { 0x6C4D69E9, 0x6699, 0x4468, { 0xA9, 0xE1, 0x69, 0x41, 0xF3, 0x8A, 0xC1, 0x89 } },
    { 0x4ABD06B2, 0x984D, 0x42BC, { 0xAB, 0xD4, 0xB4, 0xE7, 0xD3, 0xA6, 0x6E, 0x5F } },
    { 0x145F21AB, 0xD92C, 0x4EAB, { 0xAB, 0x1E, 0x5D, 0x24, 0xB9, 0x0C, 0x3C, 0x6C } },
    { 0xFE3542FE, 0xC1D3, 0x4EF8, { 0x65, 0x7C, 0x80, 0x48, 0x60, 0x6F, 0xF6, 0x70 } },
    { 0x08015350, 0x6164, 0x4D64, { 0xB1, 0xE0, 0xE7, 0x74, 0xE6, 0x94, 0xFA, 0x06 } },
    { 0xBD99C1DA, 0x24D9, 0x4C8D, { 0x94, 0x78, 0xE6, 0x8C, 0x50, 0xD8, 0x39, 0xE1 } },
    { 0x55D662CE, 0x2EC6, 0x4451, { 0xA3, 0x05, 0xBA, 0x06, 0xB5, 0x07, 0x86, 0xC5 } },
    { 0x14AFC99E, 0xE23E, 0x11E1, { 0xA2, 0x34, 0xD0, 0xDF, 0x9A, 0x35, 0xC1, 0x06 } },
    { 0x3D819F77, 0xAD7D, 0x407D, { 0x8D, 0x44, 0xE7, 0xA6, 0x1F, 0x0C, 0xB4, 0x9C } },
    { 0x4F1A9E40, 0x47A0, 0x474F, { 0xBA, 0xC3, 0x43, 0x9A, 0x63, 0xCA, 0x76, 0x6D } },
    { 0x6C4D6421, 0xCAEA, 0x7556, { 0x12, 0xFC, 0x68, 0x96, 0xAC, 0xFF, 0x32, 0x89 } },
    { 0x78792958, 0x5DCB, 0x4646, { 0x8B, 0x83, 0xE9, 0x54, 0xD3, 0x5E, 0x15, 0x69 } },
    { 0x0067835F, 0x9A50, 0x433A, { 0x8C, 0xBB, 0x85, 0x20, 0x78, 0x19, 0x78, 0x14 } },
    // { 0x65FB555D, 0x5CCA, 0x40C3, { 0x99, 0x67, 0x22, 0x79, 0x88, 0x28, 0x8D, 0xD8 } },
    // { 0xA7D8002B, 0x923B, 0x41C0, { 0x88, 0x4C, 0x3F, 0xC3, 0x79, 0x52, 0x03, 0xFA } },
    // { 0x604C1E61, 0xD51F, 0x4898, { 0xAD, 0x6D, 0xD4, 0x4C, 0xC8, 0x93, 0xBF, 0x73 } }, // dummy protocol need for asus_un65u 174CF46D-B167-4E6A-B1CD-D41E24EFA0F9
    // { 0x04C04E7F, 0x0276, 0x4D0D, { 0xA7, 0x3F, 0x1D, 0xA3, 0xC8, 0xB7, 0x08, 0xB2 } },
    // { 0xAF6EFACF, 0x7A13, 0x45A3, { 0xB1, 0xA5, 0xAA, 0xFC, 0x06, 0x1C, 0x4B, 0x79 } },
    // { 0xC5C077D6, 0xFF65, 0x4FD5, { 0xA6, 0xF1, 0x30, 0x8E, 0xE3, 0x80, 0x74, 0xD3 } },
    // { 0x0DE8BACF, 0xE00A, 0x4538, { 0xBE, 0x0D, 0x81, 0xAF, 0x93, 0x74, 0xFC, 0xC9 } },
    // { 0x7DCCA335, 0x10F2, 0x46DA, { 0xA3, 0x64, 0xF3, 0xD2, 0x85, 0x58, 0x7F, 0xCE } },
    // { 0x4113C18F, 0xD650, 0x488C, { 0x92, 0x93, 0xA0, 0x56, 0xA5, 0x0C, 0xD3, 0xF6 } },
    // { 0x01B95206, 0xCD66, 0x4C0D, { 0xA8, 0x67, 0xED, 0x42, 0x96, 0x0E, 0x07, 0xDC } },
    // { 0xE458FC74, 0x9F13, 0x4E0E, { 0xA8, 0x1E, 0xE3, 0x26, 0x05, 0xFA, 0x72, 0x47 } },
    // { 0xF49EFBE0, 0x4682, 0x4471, { 0xAE, 0x65, 0x00, 0xEF, 0xFB, 0x47, 0x70, 0xBA } },
    // { 0x71FD0C86, 0xE19B, 0x4F9C, { 0x81, 0x5D, 0xCC, 0x98, 0x31, 0xDC, 0xBA, 0xFA } },
    { 0x3779AD93, 0xB988, 0x43BC, { 0x91, 0xF0, 0x3B, 0x6C, 0x6E, 0x38, 0xFA, 0xDB } },
    { 0x51D35FDB, 0x3F8F, 0x4158, { 0xA8, 0x4A, 0xC7, 0x96, 0xE9, 0xBA, 0x26, 0xC6 } },
    { 0xBDFE5FAA, 0x2A35, 0x44BB, { 0xB1, 0x7A, 0x80, 0x84, 0xD4, 0xE2, 0xB9, 0xE9 } },
  };

  for (UINTN i = 0; i < ( sizeof(UnknownSmmFuzzProtocols) / sizeof(UnknownSmmFuzzProtocols[0])) ; i++)
  {
      Status = gBS->InstallMultipleProtocolInterfaces (
                  &Handle,
                  &UnknownSmmFuzzProtocols[i],
                  DxeBuffer,
                  NULL
                  );
      ASSERT_EFI_ERROR (Status);
  }
  
  GUID UnknownProtocolGuids[] = {
  { 0x2251CA8F, 0x02B4, 0x49F3, { 0xAD, 0x67, 0x52, 0x4E, 0xDC, 0xB3, 0xD5, 0xBB } },
  { 0xF8B84AE6, 0x8465, 0x4F95, { 0x9F, 0x0B, 0xEA, 0xAA, 0x37, 0xC6, 0x15, 0x5A } }, 
  { 0x36A2CA34, 0x82FE, 0x4D2C, { 0xAD, 0x55, 0xE4, 0xF3, 0x8B, 0x3D, 0xD9, 0xD9 } },
  { 0x8D432C0F, 0xA1EE, 0x492F, { 0x85, 0x05, 0x30, 0x3B, 0x44, 0x89, 0xE9, 0xDD } },
  { 0xCBD6965C, 0xA0AE, 0x44E2, { 0xBE, 0x60, 0x3B, 0x72, 0x1E, 0x26, 0xCE, 0xCC } },
  { 0x0DE50221, 0xFAAA, 0x45BA, { 0x90, 0xB9, 0x7B, 0xCC, 0x26, 0xEC, 0x60, 0xCF } },
  { 0xFF052503, 0x1AF9, 0x4AEB, { 0x83, 0xC4, 0xC2, 0xD4, 0xCE, 0xB1, 0x0C, 0xA3 } },

  { 0xDB9A1E3D, 0x45CB, 0x4ABB, { 0x85, 0x3B, 0xE5, 0x38, 0x7F, 0xDB, 0x2E, 0x2D } }, // EFI_LEGACY_BIOS_PROTOCOL
  { 0x4984C644, 0x3E96, 0x4152, { 0xAC, 0xA0, 0x4E, 0xA2, 0x78, 0xEA, 0xEF, 0x4E } },
  { 0x9C28BE0C, 0xEE32, 0x43D8, { 0xA2, 0x23, 0xE7, 0xC1, 0x61, 0x4E, 0xF7, 0xCA } },
  { 0x8AAFB853, 0xFB0E, 0x4A4D, { 0xB1, 0xB2, 0x81, 0xBA, 0x84, 0x2E, 0xD9, 0xFC } },
  { 0xB3C64BAC, 0x6FA2, 0x485F, { 0x96, 0x97, 0xB5, 0x12, 0x94, 0x3F, 0x9E, 0x1A } },
  { 0x00C7D289, 0x1347, 0x4DE0, { 0xBF, 0x42, 0x0E, 0x26, 0x9D, 0x0E, 0xF3, 0x4A } },
  { 0x173F9091, 0x44B6, 0x43BE, { 0x9D, 0x65, 0x98, 0x94, 0x7B, 0xD9, 0xB9, 0xD7 } },
  { 0x3F557189, 0x8DAE, 0x45AE, { 0xA0, 0xB3, 0x2B, 0x99, 0xCA, 0x7A, 0xA7, 0xA0 } },
  { 0xC965C76A, 0xD71E, 0x4E66, { 0xAB, 0x06, 0xC6, 0x23, 0x0D, 0x52, 0x84, 0x25 } },
  { 0xAC570887, 0x109A, 0x4A8A, { 0x9B, 0x37, 0x85, 0x61, 0xAB, 0xB0, 0x5F, 0xE8 } },
  { 0xCC93A70B, 0xEC27, 0x49C5, { 0x8B, 0x34, 0x13, 0x93, 0x1E, 0xFE, 0xD6, 0xE2 } },

  };
  UINTN* gUnknownProtocol = AllocatePool(100 * sizeof(UINTN));
  for (UINTN i = 0; i < 100; i++) {
    gUnknownProtocol[i] = (UINTN)UNKNOWN_FUNC_DUMMY;
  }
  for (UINTN i = 0; i < ( sizeof(UnknownProtocolGuids) / sizeof(UnknownProtocolGuids[0])) ; i++)
  {
    Status = gBS->InstallMultipleProtocolInterfaces (
      &Handle,
      &UnknownProtocolGuids[i],
      gUnknownProtocol,
      NULL
      );
    ASSERT_EFI_ERROR (Status);
  }

  (VOID)UnknownSmmFuzzProtocols;
  (VOID)Status;
}