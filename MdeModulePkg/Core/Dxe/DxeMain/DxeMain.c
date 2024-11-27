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
  EFI_STATUS Status;
  UINT64 OldInFuzz = SmmFuzzGlobalData.in_fuzz;
  SmmFuzzGlobalData.in_fuzz = 0; 
  Status = EFI_FREE_POOL_Old(Buffer);
  SmmFuzzGlobalData.in_fuzz = OldInFuzz;
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
  DEBUG((DEBUG_INFO,"EFI_LOCATE_HANDLE_FUZZ %g %lx %r\n",Protocol, Status, Status));
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

UINTN NumVendorVariables = 0;
VENDOR_VARIABLE VendorVariables[500];

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
  DEBUG((DEBUG_INFO,"EFI_GET_VARIABLE_FUZZ start %g\n",VendorGuid));
  EFI_STATUS Status;
  UINT64 OldInFuzz = SmmFuzzGlobalData.in_fuzz;
  SmmFuzzGlobalData.in_fuzz = 0; 
  Status = GetVariableOld(VariableName, VendorGuid, Attributes, DataSize, Data);
  SmmFuzzGlobalData.in_fuzz = OldInFuzz;

  if (Status == 0xA000000000000002 || Status == EFI_NOT_FOUND) {
    for (UINTN i = 0; i < NumVendorVariables; i++) {
      if (CompareGuid (&VendorVariables[i].VendorGuid, VendorGuid) && !StrCmp(VendorVariables[i].VariableName, VariableName)) {
        if (VendorVariables[i].DataSize > *DataSize) {
          *DataSize = VendorVariables[i].DataSize;
          return EFI_BUFFER_TOO_SMALL;
        }
        else {
          *Attributes = VendorVariables[i].Attributes;
          CopyMem(Data, VendorVariables[i].Data, VendorVariables[i].DataSize);
          return EFI_SUCCESS;
        }
      }
    }
    return EFI_SUCCESS;
  }
  DEBUG((DEBUG_INFO,"EFI_GET_VARIABLE_FUZZ %g %lx %r\n",VendorGuid, Status, Status));
  return Status;
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
  DEBUG((DEBUG_INFO,"EFI_SET_VARIABLE_FUZZ start %g\n",VendorGuid));
  EFI_STATUS Status;
  UINT64 OldInFuzz = SmmFuzzGlobalData.in_fuzz;
  SmmFuzzGlobalData.in_fuzz = 0; 
  Status = SetVariableOld(VariableName, VendorGuid, Attributes, DataSize, Data);
  SmmFuzzGlobalData.in_fuzz = OldInFuzz;
  if (Status == 0xA000000000000002 || Status == EFI_NOT_FOUND) {
    for (UINTN i = 0; i < NumVendorVariables; i++) {
      if (CompareGuid (&VendorVariables[i].VendorGuid, VendorGuid) && !StrCmp(VendorVariables[i].VariableName, VariableName)) {
        VendorVariables[i].Attributes = Attributes;
        VendorVariables[i].Data = ReallocatePool(VendorVariables[i].DataSize,DataSize,VendorVariables[i].Data);
        VendorVariables[i].DataSize = DataSize;
        CopyMem(VendorVariables[i].Data, Data, DataSize);
        return EFI_SUCCESS;
      }
    }
    VendorVariables[NumVendorVariables].Attributes = Attributes;
    CopyGuid(&VendorVariables[NumVendorVariables].VendorGuid, VendorGuid);
    VendorVariables[NumVendorVariables].VariableName = AllocatePool(100);
    StrCpyS(VendorVariables[NumVendorVariables].VariableName, 100, VariableName);
    VendorVariables[NumVendorVariables].Data = AllocatePool(DataSize);
    VendorVariables[NumVendorVariables].DataSize = DataSize;
    CopyMem(VendorVariables[NumVendorVariables].Data, Data, DataSize);
    NumVendorVariables++;
    return EFI_SUCCESS;
  }
  DEBUG((DEBUG_INFO,"EFI_SET_VARIABLE_FUZZ %g %lx %r\n",VendorGuid, Status, Status));
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
UINT8 UnknownProtocol[1000];
PCH_NVS_AREA_PROTOCOL mPchNvsAreaProtocol;
SA_POLICY_PROTOCOL mSaPolicyProtocol;
DXE_CPU_POLICY_PROTOCOL mDxeCpuPolicyProcotol;
EFI_ACPI_SUPPORT_PROTOCOL mEfiAcpiSupportProtocol;
EFI_POWER_MGMT_INIT_DONE_PROTOCOL mEfiPowerMgmtInitDoneProtocol;
PLATFORM_NVS_AREA_PROTOCOL mPlatformNvsAreaProtocol;

VOID InstallSmmFuzzProtocol() {
  EFI_HANDLE Handle = NULL;
  EFI_STATUS Status;


  SmmFuzzGlobalData.in_fuzz = 0;
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &Handle,
                  &gSmmFuzzDataProtocolGuid,
                  &SmmFuzzGlobalData,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);

  
  mPchNvsAreaProtocol.Area = AllocatePool(sizeof(PCH_NVS_AREA));
  ZeroMem(mPchNvsAreaProtocol.Area,sizeof(PCH_NVS_AREA));
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &Handle,
                  &gPchNvsAreaProtocolGuid,
                  &mPchNvsAreaProtocol,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);

  ZeroMem(&mSaPolicyProtocol,sizeof(SA_POLICY_PROTOCOL));
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &Handle,
                  &gSaPolicyProtocolGuid,
                  &mSaPolicyProtocol,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);

  ZeroMem(&mDxeCpuPolicyProcotol,sizeof(DXE_CPU_POLICY_PROTOCOL));
  mDxeCpuPolicyProcotol.EnableDts = 3;
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &Handle,
                  &gDxeCpuPolicyProtocolGuid,
                  &mDxeCpuPolicyProcotol,
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

  Status = gBS->InstallMultipleProtocolInterfaces (
                  &Handle,
                  &gPowerMgmtInitDoneProtocolGuid,
                  &mEfiPowerMgmtInitDoneProtocol,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);

  mPlatformNvsAreaProtocol.Area = AllocatePool(sizeof(PLATFORM_NVS_AREA));
  ZeroMem(mPlatformNvsAreaProtocol.Area,sizeof(PLATFORM_NVS_AREA));
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &Handle,
                  &gPlatformNvsAreaProtocolGuid,
                  &mPlatformNvsAreaProtocol,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);

  Status = gBS->InstallMultipleProtocolInterfaces (
                  &Handle,
                  &gUnknownHpProtocol1Guid,
                  UnknownProtocol,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);

  Status = gBS->InstallMultipleProtocolInterfaces (
                  &Handle,
                  &gUnknownHpProtocol2Guid,
                  UnknownProtocol,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);

  Status = gBS->InstallMultipleProtocolInterfaces (
                  &Handle,
                  &gUnknownHpProtocol3Guid,
                  UnknownProtocol,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);

  Status = gBS->InstallMultipleProtocolInterfaces (
                  &Handle,
                  &gUnknownHpProtocol4Guid,
                  UnknownProtocol,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);
  (VOID)Status;
}