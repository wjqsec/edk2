/** @file
  SMM Core Main Entry Point

  Copyright (c) 2009 - 2023, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "PiSmmCore.h"
extern EFI_INSTALL_PROTOCOL_INTERFACE      SmmInstallProtocolInterfaceOld;
extern EFI_UNINSTALL_PROTOCOL_INTERFACE    SmmUninstallProtocolInterfaceOld;
extern EFI_HANDLE_PROTOCOL                 SmmHandleProtocolOld;
extern EFI_SMM_REGISTER_PROTOCOL_NOTIFY    SmmRegisterProtocolNotifyOld;
extern EFI_LOCATE_HANDLE                   SmmLocateHandleOld;
extern EFI_LOCATE_PROTOCOL                 SmmLocateProtocolOld;
extern EFI_SMM_INTERRUPT_MANAGE            SmiManageOld;
extern EFI_SMM_INTERRUPT_REGISTER          SmiHandlerRegisterOld;
extern EFI_SMM_INTERRUPT_UNREGISTER        SmiHandlerUnRegisterOld;
extern EFI_ALLOCATE_POOL                   SmmAllocatePoolOld;
extern EFI_FREE_POOL                       SmmFreePoolOld;
extern EFI_ALLOCATE_PAGES                  SmmAllocatePagesOld;
extern EFI_FREE_PAGES                      SmmFreePagesOld;
extern EFI_SMM_STARTUP_THIS_AP             SmmStartupThisAp;
extern SMM_FUZZ_GLOBAL_DATA *SmmFuzzGlobalData;

GUID gEfiEndOfDxeEventGuid = {0x11111111, 0x1111, 0x1111, {0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11}};
GUID gEfiReadyToLockEventGuid = {0x22222222, 0x2222, 0x2222, {0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22}};
BOOLEAN NoCommbufCheck = FALSE;
//
// Physical pointer to private structure shared between SMM IPL and the SMM Core
//
SMM_CORE_PRIVATE_DATA  *gSmmCorePrivate;

//
// SMM Core global variable for SMM System Table.  Only accessed as a physical structure in SMRAM.
//
EFI_SMM_SYSTEM_TABLE2  gSmmCoreSmst = {
  {
    SMM_SMST_SIGNATURE,
    EFI_SMM_SYSTEM_TABLE2_REVISION,
    sizeof (gSmmCoreSmst.Hdr)
  },
  NULL,                          // SmmFirmwareVendor
  0,                             // SmmFirmwareRevision
  SmmInstallConfigurationTable,
  {
    {
      (EFI_SMM_CPU_IO2)SmmEfiNotAvailableYetArg5,        // SmmMemRead
      (EFI_SMM_CPU_IO2)SmmEfiNotAvailableYetArg5         // SmmMemWrite
    },
    {
      (EFI_SMM_CPU_IO2)SmmEfiNotAvailableYetArg5,        // SmmIoRead
      (EFI_SMM_CPU_IO2)SmmEfiNotAvailableYetArg5         // SmmIoWrite
    }
  },
  SmmAllocatePool,
  SmmFreePool,
  SmmAllocatePages,
  SmmFreePages,
  NULL,                          // SmmStartupThisAp
  0,                             // CurrentlyExecutingCpu
  0,                             // NumberOfCpus
  NULL,                          // CpuSaveStateSize
  NULL,                          // CpuSaveState
  0,                             // NumberOfTableEntries
  NULL,                          // SmmConfigurationTable
  SmmInstallProtocolInterface,
  SmmUninstallProtocolInterface,
  SmmHandleProtocol,
  SmmRegisterProtocolNotify,
  SmmLocateHandle,
  SmmLocateProtocol,
  SmiManage,
  SmiHandlerRegister,
  SmiHandlerUnRegister
};

//
// Flag to determine if the platform has performed a legacy boot.
// If this flag is TRUE, then the runtime code and runtime data associated with the
// SMM IPL are converted to free memory, so the SMM Core must guarantee that is
// does not touch of the code/data associated with the SMM IPL if this flag is TRUE.
//
BOOLEAN  mInLegacyBoot = FALSE;

//
// Flag to determine if it is during S3 resume.
// It will be set in S3 entry callback and cleared at EndOfS3Resume.
//
BOOLEAN  mDuringS3Resume = FALSE;

//
// Flag to determine if platform enabled S3.
// Get the value from PcdAcpiS3Enable.
//
BOOLEAN  mAcpiS3Enable = FALSE;

//
// Table of SMI Handlers that are registered by the SMM Core when it is initialized
//
SMM_CORE_SMI_HANDLERS  mSmmCoreSmiHandlers[] = {
  { SmmDriverDispatchHandler,   &gEfiEventDxeDispatchGuid,          NULL, TRUE  },
  { SmmReadyToLockHandler,      &gEfiDxeSmmReadyToLockProtocolGuid, NULL, TRUE  },
  { SmmLegacyBootHandler,       &gEfiEventLegacyBootGuid,           NULL, FALSE },
  { SmmExitBootServicesHandler, &gEfiEventExitBootServicesGuid,     NULL, FALSE },
  { SmmReadyToBootHandler,      &gEfiEventReadyToBootGuid,          NULL, FALSE },
  { SmmEndOfDxeHandler,         &gEfiEndOfDxeEventGroupGuid,        NULL, TRUE  },
  { NULL,                       NULL,                               NULL, FALSE }
};

//
// Table of SMI Handlers that are registered by the SMM Core when it is initialized
//
SMM_CORE_SMI_HANDLERS  mSmmCoreS3SmiHandlers[] = {
  { SmmS3SmmInitDoneHandler, &gEdkiiS3SmmInitDoneGuid, NULL, FALSE },
  { SmmEndOfS3ResumeHandler, &gEdkiiEndOfS3ResumeGuid, NULL, FALSE },
  { NULL,                    NULL,                     NULL, FALSE }
};

UINTN                 mFullSmramRangeCount;
EFI_SMRAM_DESCRIPTOR  *mFullSmramRanges;

EFI_SMM_DRIVER_ENTRY  *mSmmCoreDriverEntry;

EFI_LOADED_IMAGE_PROTOCOL  *mSmmCoreLoadedImage;

/**
  Place holder function until all the SMM System Table Service are available.

  Note: This function is only used by SMRAM invocation.  It is never used by DXE invocation.

  @param  Arg1                   Undefined
  @param  Arg2                   Undefined
  @param  Arg3                   Undefined
  @param  Arg4                   Undefined
  @param  Arg5                   Undefined

  @return EFI_NOT_AVAILABLE_YET

**/
EFI_STATUS
EFIAPI
SmmEfiNotAvailableYetArg5 (
  UINTN  Arg1,
  UINTN  Arg2,
  UINTN  Arg3,
  UINTN  Arg4,
  UINTN  Arg5
  )
{
  //
  // This function should never be executed.  If it does, then the architectural protocols
  // have not been designed correctly.
  //
  return EFI_NOT_AVAILABLE_YET;
}

/**
  Software SMI handler that is called when a Legacy Boot event is signalled.  The SMM
  Core uses this signal to know that a Legacy Boot has been performed and that
  gSmmCorePrivate that is shared between the UEFI and SMM execution environments can
  not be accessed from SMM anymore since that structure is considered free memory by
  a legacy OS. Then the SMM Core also install SMM Legacy Boot protocol to notify SMM
  driver that system enter legacy boot.

  @param  DispatchHandle  The unique handle assigned to this handler by SmiHandlerRegister().
  @param  Context         Points to an optional handler context which was specified when the handler was registered.
  @param  CommBuffer      A pointer to a collection of data in memory that will
                          be conveyed from a non-SMM environment into an SMM environment.
  @param  CommBufferSize  The size of the CommBuffer.

  @return Status Code

**/
EFI_STATUS
EFIAPI
SmmLegacyBootHandler (
  IN     EFI_HANDLE  DispatchHandle,
  IN     CONST VOID  *Context         OPTIONAL,
  IN OUT VOID        *CommBuffer      OPTIONAL,
  IN OUT UINTN       *CommBufferSize  OPTIONAL
  )
{
  EFI_STATUS  Status;
  EFI_HANDLE  SmmHandle;
  UINTN       Index;

  //
  // Install SMM Legacy Boot protocol.
  //
  SmmHandle = NULL;
  Status    = SmmInstallProtocolInterface (
                &SmmHandle,
                &gEdkiiSmmLegacyBootProtocolGuid,
                EFI_NATIVE_INTERFACE,
                NULL
                );

  mInLegacyBoot = TRUE;

  SmiHandlerUnRegister (DispatchHandle);

  //
  // It is legacy boot, unregister ExitBootService SMI handler.
  //
  for (Index = 0; mSmmCoreSmiHandlers[Index].HandlerType != NULL; Index++) {
    if (CompareGuid (mSmmCoreSmiHandlers[Index].HandlerType, &gEfiEventExitBootServicesGuid)) {
      SmiHandlerUnRegister (mSmmCoreSmiHandlers[Index].DispatchHandle);
      break;
    }
  }

  return Status;
}

/**
  Software SMI handler that is called when an Exit Boot Services event is signalled.
  Then the SMM Core also install SMM Exit Boot Services protocol to notify SMM driver
  that system enter exit boot services.

  @param  DispatchHandle  The unique handle assigned to this handler by SmiHandlerRegister().
  @param  Context         Points to an optional handler context which was specified when the handler was registered.
  @param  CommBuffer      A pointer to a collection of data in memory that will
                          be conveyed from a non-SMM environment into an SMM environment.
  @param  CommBufferSize  The size of the CommBuffer.

  @return Status Code

**/
EFI_STATUS
EFIAPI
SmmExitBootServicesHandler (
  IN     EFI_HANDLE  DispatchHandle,
  IN     CONST VOID  *Context         OPTIONAL,
  IN OUT VOID        *CommBuffer      OPTIONAL,
  IN OUT UINTN       *CommBufferSize  OPTIONAL
  )
{
  EFI_STATUS  Status;
  EFI_HANDLE  SmmHandle;
  UINTN       Index;

  //
  // Install SMM Exit Boot Services protocol.
  //
  SmmHandle = NULL;
  Status    = SmmInstallProtocolInterface (
                &SmmHandle,
                &gEdkiiSmmExitBootServicesProtocolGuid,
                EFI_NATIVE_INTERFACE,
                NULL
                );

  SmiHandlerUnRegister (DispatchHandle);

  //
  // It is UEFI boot, unregister LegacyBoot SMI handler.
  //
  for (Index = 0; mSmmCoreSmiHandlers[Index].HandlerType != NULL; Index++) {
    if (CompareGuid (mSmmCoreSmiHandlers[Index].HandlerType, &gEfiEventLegacyBootGuid)) {
      SmiHandlerUnRegister (mSmmCoreSmiHandlers[Index].DispatchHandle);
      break;
    }
  }

  return Status;
}

/**
  Main entry point for an SMM handler dispatch or communicate-based callback.

  @param[in]     DispatchHandle  The unique handle assigned to this handler by SmiHandlerRegister().
  @param[in]     Context         Points to an optional handler context which was specified when the
                                 handler was registered.
  @param[in,out] CommBuffer      A pointer to a collection of data in memory that will
                                 be conveyed from a non-SMM environment into an SMM environment.
  @param[in,out] CommBufferSize  The size of the CommBuffer.

  @retval EFI_SUCCESS                         The interrupt was handled and quiesced. No other handlers
                                              should still be called.
  @retval EFI_WARN_INTERRUPT_SOURCE_QUIESCED  The interrupt has been quiesced but other handlers should
                                              still be called.
  @retval EFI_WARN_INTERRUPT_SOURCE_PENDING   The interrupt is still pending and other handlers should still
                                              be called.
  @retval EFI_INTERRUPT_PENDING               The interrupt could not be quiesced.
**/
EFI_STATUS
EFIAPI
SmmS3EntryCallBack (
  IN           EFI_HANDLE  DispatchHandle,
  IN     CONST VOID        *Context         OPTIONAL,
  IN OUT       VOID        *CommBuffer      OPTIONAL,
  IN OUT       UINTN       *CommBufferSize  OPTIONAL
  )
{
  mDuringS3Resume = TRUE;
  return EFI_SUCCESS;
}

/**
  Software SMI handler that is called when an Ready To Boot event is signalled.
  Then the SMM Core also install SMM Ready To Boot protocol to notify SMM driver
  that system enter ready to boot.

  @param  DispatchHandle  The unique handle assigned to this handler by SmiHandlerRegister().
  @param  Context         Points to an optional handler context which was specified when the handler was registered.
  @param  CommBuffer      A pointer to a collection of data in memory that will
                          be conveyed from a non-SMM environment into an SMM environment.
  @param  CommBufferSize  The size of the CommBuffer.

  @return Status Code

**/
EFI_STATUS
EFIAPI
SmmReadyToBootHandler (
  IN     EFI_HANDLE  DispatchHandle,
  IN     CONST VOID  *Context         OPTIONAL,
  IN OUT VOID        *CommBuffer      OPTIONAL,
  IN OUT UINTN       *CommBufferSize  OPTIONAL
  )
{
  EFI_STATUS  Status;
  EFI_HANDLE  SmmHandle;

  PERF_CALLBACK_BEGIN (&gEfiEventReadyToBootGuid);

  //
  // Install SMM Ready To Boot protocol.
  //
  SmmHandle = NULL;
  Status    = SmmInstallProtocolInterface (
                &SmmHandle,
                &gEdkiiSmmReadyToBootProtocolGuid,
                EFI_NATIVE_INTERFACE,
                NULL
                );

  SmiHandlerUnRegister (DispatchHandle);

  PERF_CALLBACK_END (&gEfiEventReadyToBootGuid);
  return Status;
}

/**
  Software SMI handler that is called when the DxeSmmReadyToLock protocol is added
  or if gEfiEventReadyToBootGuid is signalled.  This function unregisters the
  Software SMIs that are nor required after SMRAM is locked and installs the
  SMM Ready To Lock Protocol so SMM Drivers are informed that SMRAM is about
  to be locked.  It also verifies the SMM CPU I/O 2 Protocol has been installed
  and NULLs gBS and gST because they can not longer be used after SMRAM is locked.

  @param  DispatchHandle  The unique handle assigned to this handler by SmiHandlerRegister().
  @param  Context         Points to an optional handler context which was specified when the handler was registered.
  @param  CommBuffer      A pointer to a collection of data in memory that will
                          be conveyed from a non-SMM environment into an SMM environment.
  @param  CommBufferSize  The size of the CommBuffer.

  @return Status Code

**/
EFI_STATUS
EFIAPI
SmmReadyToLockHandler (
  IN     EFI_HANDLE  DispatchHandle,
  IN     CONST VOID  *Context         OPTIONAL,
  IN OUT VOID        *CommBuffer      OPTIONAL,
  IN OUT UINTN       *CommBufferSize  OPTIONAL
  )
{
  EFI_STATUS  Status;
  UINTN       Index;
  EFI_HANDLE  SmmHandle;
  VOID        *Interface;
  

  PERF_CALLBACK_BEGIN (&gEfiDxeSmmReadyToLockProtocolGuid);

  //
  // Unregister SMI Handlers that are no required after the SMM driver dispatch is stopped
  //
  for (Index = 0; mSmmCoreSmiHandlers[Index].HandlerType != NULL; Index++) {
    if (mSmmCoreSmiHandlers[Index].UnRegister) {
      SmiHandlerUnRegister (mSmmCoreSmiHandlers[Index].DispatchHandle);
    }
  }
  //
  // Install SMM Ready to lock protocol
  //
  DEBUG((DEBUG_INFO,"SmmReadyToLockHandler start\n"));
  LIBAFL_QEMU_END(LIBAFL_QEMU_END_SMM_INIT_PREPARE,0,0);
  LIBAFL_QEMU_SMM_REPORT_SMM_MODULE_INFO((libafl_word)&gEfiReadyToLockEventGuid,0,0);
  SmmFuzzGlobalData->in_fuzz = 1;
  LIBAFL_QEMU_END(LIBAFL_QEMU_END_SMM_INIT_START,0,0);
  UINTN skip = LIBAFL_QEMU_SMM_ASK_SKIP_MODULE();
  Status = EFI_SUCCESS;
  if (skip == 0) {
    SmmHandle = NULL;
    Status    = SmmInstallProtocolInterface (
                  &SmmHandle,
                  &gEfiSmmReadyToLockProtocolGuid,
                  EFI_NATIVE_INTERFACE,
                  NULL
                  );
    if (EFI_ERROR(Status)) {
      LIBAFL_QEMU_END(LIBAFL_QEMU_END_SMM_INIT_ERROR,0,0);
    }
  }
  LIBAFL_QEMU_END(LIBAFL_QEMU_END_SMM_INIT_END,0,0);  
  SmmFuzzGlobalData->in_fuzz = 0;
  DEBUG((DEBUG_INFO,"SmmReadyToLockHandler end\n"));
  //
  // Make sure SMM CPU I/O 2 Protocol has been installed into the handle database
  //
  Status = SmmLocateProtocol (&gEfiSmmCpuIo2ProtocolGuid, NULL, &Interface);

  //
  // Print a message on a debug build if the SMM CPU I/O 2 Protocol is not installed
  //
  DEBUG_CODE_BEGIN ();
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "\nSMM: SmmCpuIo Arch Protocol not present!!\n"));
  }

  DEBUG_CODE_END ();

  //
  // Assert if the CPU I/O 2 Protocol is not installed
  //
  ASSERT_EFI_ERROR (Status);

  //
  // Display any drivers that were not dispatched because dependency expression
  // evaluated to false if this is a debug build
  //
  DEBUG_CODE_BEGIN ();
  SmmDisplayDiscoveredNotDispatched ();
  DEBUG_CODE_END ();

  //
  // Not allowed to use gST or gBS after lock
  //
  gST = NULL;
  gBS = NULL;

  SmmFuzzGlobalData->in_fuzz = 0;
  SmramProfileReadyToLock ();

  PERF_CALLBACK_END (&gEfiDxeSmmReadyToLockProtocolGuid);
  return Status;
}

/**
  Software SMI handler that is called when the EndOfDxe event is signalled.
  This function installs the SMM EndOfDxe Protocol so SMM Drivers are informed that
  platform code will invoke 3rd part code.

  @param  DispatchHandle  The unique handle assigned to this handler by SmiHandlerRegister().
  @param  Context         Points to an optional handler context which was specified when the handler was registered.
  @param  CommBuffer      A pointer to a collection of data in memory that will
                          be conveyed from a non-SMM environment into an SMM environment.
  @param  CommBufferSize  The size of the CommBuffer.

  @return Status Code

**/
EFI_STATUS
EFIAPI
SmmEndOfDxeHandler (
  IN     EFI_HANDLE  DispatchHandle,
  IN     CONST VOID  *Context         OPTIONAL,
  IN OUT VOID        *CommBuffer      OPTIONAL,
  IN OUT UINTN       *CommBufferSize  OPTIONAL
  )
{
  EFI_STATUS                     Status;
  EFI_HANDLE                     SmmHandle;
  EFI_SMM_SX_DISPATCH2_PROTOCOL  *SxDispatch;
  EFI_SMM_SX_REGISTER_CONTEXT    EntryRegisterContext;
  EFI_HANDLE                     S3EntryHandle;



  PERF_CALLBACK_BEGIN (&gEfiEndOfDxeEventGroupGuid);

  //
  // Install SMM EndOfDxe protocol
  //
  DEBUG ((DEBUG_INFO, "SmmEndOfDxeHandler\n"));
  LIBAFL_QEMU_END(LIBAFL_QEMU_END_SMM_INIT_PREPARE,0,0);
  LIBAFL_QEMU_SMM_REPORT_SMM_MODULE_INFO((libafl_word)&gEfiEndOfDxeEventGuid,0,0);
  SmmFuzzGlobalData->in_fuzz = 1;
  LIBAFL_QEMU_END(LIBAFL_QEMU_END_SMM_INIT_START,0,0);
  UINTN skip = LIBAFL_QEMU_SMM_ASK_SKIP_MODULE();
  Status = EFI_SUCCESS;
  if (skip == 0) {
    SmmHandle = NULL;
    Status    = SmmInstallProtocolInterface (
                  &SmmHandle,
                  &gEfiSmmEndOfDxeProtocolGuid,
                  EFI_NATIVE_INTERFACE,
                  NULL
                  );
    if (EFI_ERROR(Status)) {
      LIBAFL_QEMU_END(LIBAFL_QEMU_END_SMM_INIT_ERROR,0,0);
    }
  }
  LIBAFL_QEMU_END(LIBAFL_QEMU_END_SMM_INIT_END,0,0);  
  SmmFuzzGlobalData->in_fuzz = 0;
  DEBUG ((DEBUG_INFO, "SmmEndOfDxeHandler end\n"));                
  if (mAcpiS3Enable) {
    //
    // Locate SmmSxDispatch2 protocol.
    //
    Status = SmmLocateProtocol (
               &gEfiSmmSxDispatch2ProtocolGuid,
               NULL,
               (VOID **)&SxDispatch
               );
    if (!EFI_ERROR (Status) && (SxDispatch != NULL)) {
      //
      // Register a S3 entry callback function to
      // determine if it will be during S3 resume.
      //
      EntryRegisterContext.Type  = SxS3;
      EntryRegisterContext.Phase = SxEntry;
      Status                     = SxDispatch->Register (
                                                 SxDispatch,
                                                 SmmS3EntryCallBack,
                                                 &EntryRegisterContext,
                                                 &S3EntryHandle
                                                 );
      ASSERT_EFI_ERROR (Status);
    }
  }

  PERF_CALLBACK_END (&gEfiEndOfDxeEventGroupGuid);
  return EFI_SUCCESS;
}

/**
  Software SMI handler that is called when the S3SmmInitDone signal is triggered.
  This function installs the SMM S3SmmInitDone Protocol so SMM Drivers are informed that
  S3 SMM initialization has been done.

  @param  DispatchHandle  The unique handle assigned to this handler by SmiHandlerRegister().
  @param  Context         Points to an optional handler context which was specified when the handler was registered.
  @param  CommBuffer      A pointer to a collection of data in memory that will
                          be conveyed from a non-SMM environment into an SMM environment.
  @param  CommBufferSize  The size of the CommBuffer.

  @return Status Code

**/
EFI_STATUS
EFIAPI
SmmS3SmmInitDoneHandler (
  IN     EFI_HANDLE  DispatchHandle,
  IN     CONST VOID  *Context         OPTIONAL,
  IN OUT VOID        *CommBuffer      OPTIONAL,
  IN OUT UINTN       *CommBufferSize  OPTIONAL
  )
{
  EFI_STATUS  Status;
  EFI_HANDLE  SmmHandle;

  DEBUG ((DEBUG_INFO, "SmmS3SmmInitDoneHandler\n"));

  if (!mDuringS3Resume) {
    DEBUG ((DEBUG_ERROR, "It is not during S3 resume\n"));
    return EFI_SUCCESS;
  }

  //
  // Install SMM S3SmmInitDone protocol
  //
  SmmHandle = NULL;
  Status    = SmmInstallProtocolInterface (
                &SmmHandle,
                &gEdkiiS3SmmInitDoneGuid,
                EFI_NATIVE_INTERFACE,
                NULL
                );
  ASSERT_EFI_ERROR (Status);

  //
  // Uninstall the protocol here because the comsumer just hook the
  // installation event.
  //
  Status = SmmUninstallProtocolInterface (
             SmmHandle,
             &gEdkiiS3SmmInitDoneGuid,
             NULL
             );
  ASSERT_EFI_ERROR (Status);

  return Status;
}

/**
  Software SMI handler that is called when the EndOfS3Resume signal is triggered.
  This function installs the SMM EndOfS3Resume Protocol so SMM Drivers are informed that
  S3 resume has finished.

  @param  DispatchHandle  The unique handle assigned to this handler by SmiHandlerRegister().
  @param  Context         Points to an optional handler context which was specified when the handler was registered.
  @param  CommBuffer      A pointer to a collection of data in memory that will
                          be conveyed from a non-SMM environment into an SMM environment.
  @param  CommBufferSize  The size of the CommBuffer.

  @return Status Code

**/
EFI_STATUS
EFIAPI
SmmEndOfS3ResumeHandler (
  IN     EFI_HANDLE  DispatchHandle,
  IN     CONST VOID  *Context         OPTIONAL,
  IN OUT VOID        *CommBuffer      OPTIONAL,
  IN OUT UINTN       *CommBufferSize  OPTIONAL
  )
{
  EFI_STATUS  Status;
  EFI_HANDLE  SmmHandle;

  DEBUG ((DEBUG_INFO, "SmmEndOfS3ResumeHandler\n"));

  if (!mDuringS3Resume) {
    DEBUG ((DEBUG_ERROR, "It is not during S3 resume\n"));
    return EFI_SUCCESS;
  }

  //
  // Install SMM EndOfS3Resume protocol
  //
  SmmHandle = NULL;
  Status    = SmmInstallProtocolInterface (
                &SmmHandle,
                &gEdkiiEndOfS3ResumeGuid,
                EFI_NATIVE_INTERFACE,
                NULL
                );
  ASSERT_EFI_ERROR (Status);

  //
  // Uninstall the protocol here because the consumer just hook the
  // installation event.
  //
  Status = SmmUninstallProtocolInterface (
             SmmHandle,
             &gEdkiiEndOfS3ResumeGuid,
             NULL
             );
  ASSERT_EFI_ERROR (Status);

  mDuringS3Resume = FALSE;
  return Status;
}

/**
  Determine if two buffers overlap in memory.

  @param[in] Buff1  Pointer to first buffer
  @param[in] Size1  Size of Buff1
  @param[in] Buff2  Pointer to second buffer
  @param[in] Size2  Size of Buff2

  @retval TRUE      Buffers overlap in memory.
  @retval TRUE      Math error.     Prevents potential math over and underflows.
  @retval FALSE     Buffer doesn't overlap.

**/
BOOLEAN
InternalIsBufferOverlapped (
  IN UINT8  *Buff1,
  IN UINTN  Size1,
  IN UINT8  *Buff2,
  IN UINTN  Size2
  )
{
  UINTN    End1;
  UINTN    End2;
  BOOLEAN  IsOverUnderflow1;
  BOOLEAN  IsOverUnderflow2;

  // Check for over or underflow
  IsOverUnderflow1 = EFI_ERROR (SafeUintnAdd ((UINTN)Buff1, Size1, &End1));
  IsOverUnderflow2 = EFI_ERROR (SafeUintnAdd ((UINTN)Buff2, Size2, &End2));

  if (IsOverUnderflow1 || IsOverUnderflow2) {
    return TRUE;
  }

  //
  // If buff1's end is less than the start of buff2, then it's ok.
  // Also, if buff1's start is beyond buff2's end, then it's ok.
  //
  if ((End1 <= (UINTN)Buff2) || ((UINTN)Buff1 >= End2)) {
    return FALSE;
  }

  return TRUE;
}

/**
  The main entry point to SMM Foundation.

  Note: This function is only used by SMRAM invocation.  It is never used by DXE invocation.

  @param  SmmEntryContext           Processor information and functionality
                                    needed by SMM Foundation.

**/
VOID
EFIAPI
SmmEntryPoint (
  IN CONST EFI_SMM_ENTRY_CONTEXT  *SmmEntryContext
  )
{
  EFI_STATUS                  Status;
  EFI_SMM_COMMUNICATE_HEADER  *CommunicateHeader;
  BOOLEAN                     InLegacyBoot;
  BOOLEAN                     IsOverlapped;
  BOOLEAN                     IsOverUnderflow;
  VOID                        *CommunicationBuffer;
  UINTN                       BufferSize;
  
  PERF_FUNCTION_BEGIN ();
  //
  // Update SMST with contents of the SmmEntryContext structure
  //
  gSmmCorePrivate->Smst->SmmStartupThisAp      = SmmEntryContext->SmmStartupThisAp;
  gSmmCorePrivate->Smst->CurrentlyExecutingCpu = SmmEntryContext->CurrentlyExecutingCpu;
  gSmmCorePrivate->Smst->NumberOfCpus          = SmmEntryContext->NumberOfCpus;
  gSmmCorePrivate->Smst->CpuSaveStateSize      = SmmEntryContext->CpuSaveStateSize;
  gSmmCorePrivate->Smst->CpuSaveState          = SmmEntryContext->CpuSaveState;
  //
  // Call platform hook before Smm Dispatch
  //
  PERF_START (NULL, "PlatformHookBeforeSmmDispatch", NULL, 0);
  PlatformHookBeforeSmmDispatch ();
  PERF_END (NULL, "PlatformHookBeforeSmmDispatch", NULL, 0);

  //
  // Call memory management hook function
  //
  SmmEntryPointMemoryManagementHook ();
  
  //
  // If a legacy boot has occurred, then make sure gSmmCorePrivate is not accessed
  //
  InLegacyBoot = mInLegacyBoot;
  if (!InLegacyBoot) {
    //
    // Mark the InSmm flag as TRUE, it will be used by SmmBase2 protocol
    //
    gSmmCorePrivate->InSmm = TRUE;

    //
    // Check to see if this is a Synchronous SMI sent through the SMM Communication
    // Protocol or an Asynchronous SMI
    //
    CommunicationBuffer = gSmmCorePrivate->CommunicationBuffer;
    BufferSize          = gSmmCorePrivate->BufferSize;
    if (CommunicationBuffer != NULL) {
      //
      // Synchronous SMI for SMM Core or request from Communicate protocol
      //
      IsOverlapped = InternalIsBufferOverlapped (
                       (UINT8 *)CommunicationBuffer,
                       BufferSize,
                       (UINT8 *)gSmmCorePrivate,
                       sizeof (*gSmmCorePrivate)
                       );
      //
      // Check for over or underflows
      //
      IsOverUnderflow = EFI_ERROR (SafeUintnSub (BufferSize, OFFSET_OF (EFI_SMM_COMMUNICATE_HEADER, Data), &BufferSize));

      if (!NoCommbufCheck && (!SmmIsBufferOutsideSmmValid ((UINTN)CommunicationBuffer, BufferSize) ||
          IsOverlapped || IsOverUnderflow))
      {
        //
        // If CommunicationBuffer is not in valid address scope,
        // or there is overlap between gSmmCorePrivate and CommunicationBuffer,
        // or there is over or underflow,
        // return EFI_INVALID_PARAMETER
        //
        gSmmCorePrivate->CommunicationBuffer = NULL;
        gSmmCorePrivate->ReturnStatus        = EFI_ACCESS_DENIED;
      } 
      else 
      {
        CommunicateHeader = (EFI_SMM_COMMUNICATE_HEADER *)CommunicationBuffer;
        // BufferSize was updated by the SafeUintnSub() call above. 
        Status = SmiManage (
                   &CommunicateHeader->HeaderGuid,
                   NULL,
                   CommunicateHeader->Data,
                   &BufferSize
                   );
        //
        // Update CommunicationBuffer, BufferSize and ReturnStatus
        // Communicate service finished, reset the pointer to CommBuffer to NULL
        //
        gSmmCorePrivate->BufferSize          = BufferSize + OFFSET_OF (EFI_SMM_COMMUNICATE_HEADER, Data);
        gSmmCorePrivate->CommunicationBuffer = NULL;
        gSmmCorePrivate->ReturnStatus        = (Status == EFI_SUCCESS) ? EFI_SUCCESS : EFI_NOT_FOUND;
      }
    }
  }

  //
  // Process Asynchronous SMI sources
  //
  // SmiManage (NULL, NULL, NULL, NULL);

  //
  // Call platform hook after Smm Dispatch
  //
  PERF_START (NULL, "PlatformHookAfterSmmDispatch", NULL, 0);
  PlatformHookAfterSmmDispatch ();
  PERF_END (NULL, "PlatformHookAfterSmmDispatch", NULL, 0);

  //
  // If a legacy boot has occurred, then make sure gSmmCorePrivate is not accessed
  //
  if (!InLegacyBoot) {
    //
    // Clear the InSmm flag as we are going to leave SMM
    //
    gSmmCorePrivate->InSmm = FALSE;
  }

  PERF_FUNCTION_END ();
}
VOID
EFIAPI
SmmEntryPointFuzz (
  IN CONST EFI_SMM_ENTRY_CONTEXT  *SmmEntryContext
  )
{
  UINT64 OldInFuzz = SmmFuzzGlobalData->in_fuzz;
  SmmFuzzGlobalData->in_fuzz = 0;
  SmmEntryPoint(SmmEntryContext);
  SmmFuzzGlobalData->in_fuzz = OldInFuzz;
}
/**
  Install LoadedImage protocol for SMM Core.
**/
VOID
SmmCoreInstallLoadedImage (
  VOID
  )
{
  EFI_STATUS  Status;
  EFI_HANDLE  Handle;

  //
  // Allocate a Loaded Image Protocol in EfiBootServicesData
  //
  Status = gBS->AllocatePool (EfiBootServicesData, sizeof (EFI_LOADED_IMAGE_PROTOCOL), (VOID **)&mSmmCoreLoadedImage);
  ASSERT_EFI_ERROR (Status);

  ZeroMem (mSmmCoreLoadedImage, sizeof (EFI_LOADED_IMAGE_PROTOCOL));
  //
  // Fill in the remaining fields of the Loaded Image Protocol instance.
  // Note: ImageBase is an SMRAM address that can not be accessed outside of SMRAM if SMRAM window is closed.
  //
  mSmmCoreLoadedImage->Revision     = EFI_LOADED_IMAGE_PROTOCOL_REVISION;
  mSmmCoreLoadedImage->ParentHandle = gSmmCorePrivate->SmmIplImageHandle;
  mSmmCoreLoadedImage->SystemTable  = gST;

  mSmmCoreLoadedImage->ImageBase     = (VOID *)(UINTN)gSmmCorePrivate->PiSmmCoreImageBase;
  mSmmCoreLoadedImage->ImageSize     = gSmmCorePrivate->PiSmmCoreImageSize;
  mSmmCoreLoadedImage->ImageCodeType = EfiRuntimeServicesCode;
  mSmmCoreLoadedImage->ImageDataType = EfiRuntimeServicesData;

  //
  // Create a new image handle in the UEFI handle database for the SMM Driver
  //
  Handle = NULL;
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &Handle,
                  &gEfiLoadedImageProtocolGuid,
                  mSmmCoreLoadedImage,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);

  //
  // Allocate a Loaded Image Protocol in SMM
  //
  Status = SmmAllocatePool (EfiRuntimeServicesData, sizeof (EFI_SMM_DRIVER_ENTRY), (VOID **)&mSmmCoreDriverEntry);
  ASSERT_EFI_ERROR (Status);

  ZeroMem (mSmmCoreDriverEntry, sizeof (EFI_SMM_DRIVER_ENTRY));
  //
  // Fill in the remaining fields of the Loaded Image Protocol instance.
  //
  mSmmCoreDriverEntry->Signature                   = EFI_SMM_DRIVER_ENTRY_SIGNATURE;
  mSmmCoreDriverEntry->SmmLoadedImage.Revision     = EFI_LOADED_IMAGE_PROTOCOL_REVISION;
  mSmmCoreDriverEntry->SmmLoadedImage.ParentHandle = gSmmCorePrivate->SmmIplImageHandle;
  mSmmCoreDriverEntry->SmmLoadedImage.SystemTable  = gST;

  mSmmCoreDriverEntry->SmmLoadedImage.ImageBase     = (VOID *)(UINTN)gSmmCorePrivate->PiSmmCoreImageBase;
  mSmmCoreDriverEntry->SmmLoadedImage.ImageSize     = gSmmCorePrivate->PiSmmCoreImageSize;
  mSmmCoreDriverEntry->SmmLoadedImage.ImageCodeType = EfiRuntimeServicesCode;
  mSmmCoreDriverEntry->SmmLoadedImage.ImageDataType = EfiRuntimeServicesData;

  mSmmCoreDriverEntry->ImageEntryPoint = gSmmCorePrivate->PiSmmCoreEntryPoint;
  mSmmCoreDriverEntry->ImageBuffer     = gSmmCorePrivate->PiSmmCoreImageBase;
  mSmmCoreDriverEntry->NumberOfPage    = EFI_SIZE_TO_PAGES ((UINTN)gSmmCorePrivate->PiSmmCoreImageSize);

  //
  // Create a new image handle in the SMM handle database for the SMM Driver
  //
  mSmmCoreDriverEntry->SmmImageHandle = NULL;
  Status                              = SmmInstallProtocolInterface (
                                          &mSmmCoreDriverEntry->SmmImageHandle,
                                          &gEfiLoadedImageProtocolGuid,
                                          EFI_NATIVE_INTERFACE,
                                          &mSmmCoreDriverEntry->SmmLoadedImage
                                          );
  ASSERT_EFI_ERROR (Status);

  return;
}

EFI_STATUS
EFIAPI EFI_MM_STARTUP_THIS_AP_FUZZ(
  IN EFI_AP_PROCEDURE  Procedure,
  IN UINTN             CpuNumber,
  IN OUT VOID          *ProcArguments OPTIONAL
  )
{
  DEBUG((DEBUG_INFO,"EFI_MM_STARTUP_THIS_AP_FUZZ\n"));
  return EFI_SUCCESS;
}

EFI_STATUS LoadVendorCore(  IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE  *SystemTable) 
{
  EFI_STATUS Status;
  UINTN                          HandleCount;
  EFI_HANDLE                     *HandleBuffer;
  UINTN                          HandleIndex;
  EFI_HANDLE                     FvHandle;
  EFI_FIRMWARE_VOLUME2_PROTOCOL  *Fv;
  UINTN                          Key;
  EFI_STATUS                     GetNextFileStatus;
  EFI_FV_FILETYPE                Type;
  EFI_GUID                       NameGuid;
  EFI_FV_FILE_ATTRIBUTES         Attributes;
  UINTN                          Size;

  GUID SMMCORE_GUID = {0xE94F54CD, 0x81EB, 0x47ed, {0xAE, 0xC3, 0x85, 0x6F, 0x5D, 0xC1, 0x57, 0xAA}};
  GUID OLD_SMMCORE_GUID = {0xE94F54CD, 0x81EB, 0x47ed, {0xAE, 0xC3, 0x85, 0x6F, 0x5D, 0xC1, 0x57, 0xA9}};
  (VOID)SMMCORE_GUID;
  (VOID)OLD_SMMCORE_GUID;
  Status = gBS->LocateHandleBuffer (
                        ByProtocol,
                        &gEfiFirmwareVolume2ProtocolGuid,
                        NULL,
                        &HandleCount,
                        &HandleBuffer
                        );
  Type = EFI_FV_FILETYPE_SMM_CORE;
  for (HandleIndex = 0; HandleIndex < HandleCount; HandleIndex++) {
    FvHandle = HandleBuffer[HandleIndex];
    Status = gBS->HandleProtocol (FvHandle, &gEfiFirmwareVolume2ProtocolGuid, (VOID **)&Fv);
    Key = 0;
    while (TRUE) {
      GetNextFileStatus = Fv->GetNextFile (
                                  Fv,
                                  &Key,
                                  &Type,
                                  &NameGuid,
                                  &Attributes,
                                  &Size
                                  );
      if(EFI_ERROR(GetNextFileStatus))
        return EFI_NOT_FOUND; 
      if (!CompareGuid(&NameGuid, &SMMCORE_GUID)) {
          EFI_SMM_DRIVER_ENTRY  *DriverEntry;
          DriverEntry = AllocateZeroPool (sizeof (EFI_SMM_DRIVER_ENTRY));
          ASSERT (DriverEntry != NULL);
          DriverEntry->Signature = EFI_SMM_DRIVER_ENTRY_SIGNATURE;
          CopyGuid (&DriverEntry->FileName, &NameGuid);
          DriverEntry->FvHandle         = FvHandle;
          DriverEntry->Fv               = Fv;
          DriverEntry->FvFileDevicePath = SmmFvToDevicePath (Fv, FvHandle, &NameGuid);
          DEBUG((DEBUG_INFO,"start load vendor smm core\n"));
          Status = SmmLoadImage (DriverEntry);
          ASSERT_EFI_ERROR (Status);
          // Status = RegisterSmramProfileImage (DriverEntry, TRUE);
          // ASSERT_EFI_ERROR (Status);
          EFI_SMRAM_DESCRIPTOR *OldSmramRange;
          EFI_SMRAM_DESCRIPTOR *TmpSmramRange;
          Status = gBS->AllocatePool (EfiBootServicesData, gSmmCorePrivate->SmramRangeCount * sizeof(EFI_SMRAM_DESCRIPTOR), (VOID **)&TmpSmramRange);
          ASSERT_EFI_ERROR (Status);
          CopyMem(TmpSmramRange, gSmmCorePrivate->SmramRanges, gSmmCorePrivate->SmramRangeCount * sizeof(EFI_SMRAM_DESCRIPTOR));
          OldSmramRange = gSmmCorePrivate->SmramRanges;
          gSmmCorePrivate->SmramRanges = TmpSmramRange;
          UINTN i = 0;
          for (; i < gSmmCorePrivate->SmramRangeCount; i++)
          {
            if ((gSmmCorePrivate->SmramRanges[i].RegionState == 0x1A) && (gSmmCorePrivate->SmramRanges[i].PhysicalSize == VENDOR_CORE_HEAP_SIZE)) {
              break;
            }
          }
          gSmmCorePrivate->SmramRanges[i].RegionState = 0xA;
          gSmmCorePrivate->SmramRanges[i + 1].RegionState = 0x1A;
          for (UINTN i = 0 ; i < gSmmCorePrivate->SmramRangeCount; i++)
          {
            DEBUG((DEBUG_INFO,"smram record  %p %p %x %x\n",gSmmCorePrivate->SmramRanges[i].CpuStart, gSmmCorePrivate->SmramRanges[i].PhysicalStart, gSmmCorePrivate->SmramRanges[i].PhysicalSize, gSmmCorePrivate->SmramRanges[i].RegionState));
          }
          DriverEntry->ImageHandle = ImageHandle;
          Status = FuzzOneModule(DriverEntry);
          DriverEntry->SuccessfullyInited = TRUE;
          gSmmCorePrivate->SmramRanges = OldSmramRange;
          return Status;
      }
    }
  }
  return EFI_NOT_FOUND;

}
__uint128_t SmmFuzzDummyMemory = 10;
extern VOID *FuzzHobAddr;
/**
  The Entry Point for SMM Core

  Install DXE Protocols and reload SMM Core into SMRAM and register SMM Core
  EntryPoint on the SMI vector.

  Note: This function is called for both DXE invocation and SMRAM invocation.

  @param  ImageHandle    The firmware allocated handle for the EFI image.
  @param  SystemTable    A pointer to the EFI System Table.

  @retval EFI_SUCCESS    The entry point is executed successfully.
  @retval Other          Some error occurred when executing this entry point.

**/
EFI_STATUS
EFIAPI
SmmMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  
  EFI_STATUS  Status;
  UINTN       Index;
  LIBAFL_QEMU_SMM_REPORT_DUMMY_MEM((libafl_word)&SmmFuzzDummyMemory);
  Status = gBS->LocateProtocol (&gSmmFuzzDataProtocolGuid, NULL, (VOID **)&SmmFuzzGlobalData);
  ASSERT(!EFI_ERROR(Status));
  Status = gBS->AllocatePool(EfiBootServicesData, 0x1200, (VOID**)&FuzzHobAddr);
  ASSERT(!EFI_ERROR(Status));
  //
  // Get SMM Core Private context passed in from SMM IPL in ImageHandle.
  //
  gSmmCorePrivate = (SMM_CORE_PRIVATE_DATA *)ImageHandle;
  GUID SMMCORE_GUID = {0xE94F54CD, 0x81EB, 0x47ed, {0xAE, 0xC3, 0x85, 0x6F, 0x5D, 0xC1, 0x57, 0xAA}};
  InsertNewSmmModule(&SMMCORE_GUID, (VOID*)gSmmCorePrivate->PiSmmCoreImageBase, gSmmCorePrivate->PiSmmCoreImageSize);
  LIBAFL_QEMU_SMM_REPORT_SMM_MODULE_INFO((UINTN)&SMMCORE_GUID, (UINT64)gSmmCorePrivate->PiSmmCoreImageBase, (UINT64)gSmmCorePrivate->PiSmmCoreImageBase + (UINT64)gSmmCorePrivate->PiSmmCoreImageSize);
  Status = LoadVendorCore(ImageHandle, SystemTable);
  if (!EFI_ERROR(Status))
  {
      VOID *VendorCoreImageProtocol;
      EFI_HANDLE TmpHandle = NULL;
      Status = SmmLocateProtocol(&gEfiLoadedImageProtocolGuid, NULL, &VendorCoreImageProtocol);
      ASSERT(!EFI_ERROR(Status));
      Status = gSmmCorePrivate->Smst->SmmInstallProtocolInterface(&TmpHandle, &gEfiLoadedImageProtocolGuid, EFI_NATIVE_INTERFACE, VendorCoreImageProtocol);
      ASSERT(!EFI_ERROR(Status));
      SmmInstallProtocolInterfaceOld = gSmmCorePrivate->Smst->SmmInstallProtocolInterface;
      SmmUninstallProtocolInterfaceOld = gSmmCorePrivate->Smst->SmmUninstallProtocolInterface;
      SmmHandleProtocolOld = gSmmCorePrivate->Smst->SmmHandleProtocol;
      SmmRegisterProtocolNotifyOld = gSmmCorePrivate->Smst->SmmRegisterProtocolNotify;
      SmmLocateHandleOld = gSmmCorePrivate->Smst->SmmLocateHandle;
      SmmLocateProtocolOld = gSmmCorePrivate->Smst->SmmLocateProtocol;
      SmiManageOld = gSmmCorePrivate->Smst->SmiManage;
      SmiHandlerRegisterOld = gSmmCorePrivate->Smst->SmiHandlerRegister;
      SmiHandlerUnRegisterOld = gSmmCorePrivate->Smst->SmiHandlerUnRegister;
      SmmAllocatePoolOld = gSmmCorePrivate->Smst->SmmAllocatePool;
      SmmFreePoolOld = gSmmCorePrivate->Smst->SmmFreePool;
      SmmAllocatePagesOld = gSmmCorePrivate->Smst->SmmAllocatePages;
      SmmFreePagesOld = gSmmCorePrivate->Smst->SmmFreePages;
      SmmStartupThisAp = gSmmCorePrivate->Smst->SmmStartupThisAp;
  }
  else 
  {
    //
    // Fill in SMRAM physical address for the SMM Services Table and the SMM Entry Point.
    //
    gSmmCorePrivate->Smst          = &gSmmCoreSmst;
  }

  {
    gSmmCorePrivate->SmmEntryPoint = SmmEntryPointFuzz;
    gSmmCorePrivate->Smst->SmmInstallConfigurationTable = SmmInstallConfigurationTableFuzz;
    gSmmCorePrivate->Smst->SmmInstallProtocolInterface = SmmInstallProtocolInterfaceFuzz;
    gSmmCorePrivate->Smst->SmmUninstallProtocolInterface = SmmUninstallProtocolInterfaceFuzz;
    gSmmCorePrivate->Smst->SmmHandleProtocol = SmmHandleProtocolFuzz;
    gSmmCorePrivate->Smst->SmmRegisterProtocolNotify = SmmRegisterProtocolNotifyFuzz;
    gSmmCorePrivate->Smst->SmmLocateHandle = SmmLocateHandleFuzz;
    gSmmCorePrivate->Smst->SmmLocateProtocol = SmmLocateProtocolFuzz;
    gSmmCorePrivate->Smst->SmiManage = SmiManageFuzz;
    gSmmCorePrivate->Smst->SmiHandlerRegister = SmiHandlerRegisterFuzz;
    gSmmCorePrivate->Smst->SmiHandlerUnRegister = SmiHandlerUnRegisterFuzz;
    gSmmCorePrivate->Smst->SmmAllocatePool = SmmAllocatePoolFuzz;
    gSmmCorePrivate->Smst->SmmFreePool = SmmFreePoolFuzz;
    gSmmCorePrivate->Smst->SmmAllocatePages = SmmAllocatePagesFuzz;
    gSmmCorePrivate->Smst->SmmFreePages = SmmFreePagesFuzz;
  }
  //
  // No need to initialize memory service.
  // It is done in constructor of PiSmmCoreMemoryAllocationLib(),
  // so that the library linked with PiSmmCore can use AllocatePool() in constructor.
  //

  SmramProfileInit ();

  //
  // Copy FullSmramRanges to SMRAM
  //
  mFullSmramRangeCount = gSmmCorePrivate->SmramRangeCount;
  mFullSmramRanges     = AllocatePool (mFullSmramRangeCount * sizeof (EFI_SMRAM_DESCRIPTOR));
  ASSERT (mFullSmramRanges != NULL);
  CopyMem (mFullSmramRanges, gSmmCorePrivate->SmramRanges, mFullSmramRangeCount * sizeof (EFI_SMRAM_DESCRIPTOR));

  //
  // Register all SMI Handlers required by the SMM Core
  //
  for (Index = 0; mSmmCoreSmiHandlers[Index].HandlerType != NULL; Index++) {
    Status = SmiHandlerRegister (
              mSmmCoreSmiHandlers[Index].Handler,
              mSmmCoreSmiHandlers[Index].HandlerType,
              &mSmmCoreSmiHandlers[Index].DispatchHandle
              );
    ASSERT_EFI_ERROR (Status);
  }

  mAcpiS3Enable = PcdGetBool (PcdAcpiS3Enable);
  if (mAcpiS3Enable) {
    //
    // Register all S3 related SMI Handlers required by the SMM Core
    //
    for (Index = 0; mSmmCoreS3SmiHandlers[Index].HandlerType != NULL; Index++) {
      Status = SmiHandlerRegister (
                mSmmCoreS3SmiHandlers[Index].Handler,
                mSmmCoreS3SmiHandlers[Index].HandlerType,
                &mSmmCoreS3SmiHandlers[Index].DispatchHandle
                );
      ASSERT_EFI_ERROR (Status);
    }
  }

  RegisterSmramProfileHandler ();
  SmramProfileInstallProtocol ();

  SmmCoreInstallLoadedImage ();

  SmmCoreInitializeMemoryAttributesTable ();

  SmmCoreInitializeSmiHandlerProfile ();

  InstallSmmFuzzSmiHandler();
  return EFI_SUCCESS;
}

GUID RootHandlerGuids[] = {
  { 0x41A5B687, 0x7266, 0x432D, { 0x9B, 0x7C, 0xC1, 0xF7, 0xEB, 0x78, 0xE6, 0x4F } },
  { 0x5DE78512, 0x66FB, 0x4A37, { 0xAA, 0x5E, 0x84, 0xB3, 0x64, 0x0F, 0x62, 0x5A } },
  { 0x72CB5B61, 0x345F, 0x4824, { 0xB2, 0x38, 0xA3, 0x72, 0x4E, 0x1F, 0xD9, 0x67 } },
  { 0xA49E3246, 0xD8A3, 0x4A3E, { 0x8F, 0xD5, 0x5B, 0x92, 0xCE, 0x37, 0x23, 0xF1 } },
  { 0x1D7E6F87, 0x84F5, 0x4CF9, { 0x93, 0x26, 0x7D, 0xBC, 0xA3, 0xB1, 0x47, 0x2A } },
  { 0x9165C173, 0x0D5A, 0x4BEC, { 0x8E, 0xF5, 0xE3, 0xBA, 0xA1, 0x39, 0x09, 0x5A } },
  { 0xBC95DD49, 0x2ED3, 0x4EEB, { 0xA6, 0x49, 0xBB, 0xBB, 0x0D, 0xCF, 0x23, 0x74 } },
  { 0x5D330824, 0xD2F7, 0x4690, { 0xB1, 0x48, 0x56, 0x43, 0xE7, 0x9A, 0x35, 0x1A } },
  { 0xA6319C52, 0x1706, 0x4325, { 0xA8, 0xAA, 0xE1, 0x60, 0x79, 0x80, 0xEE, 0xE4 } },
  { 0x2BD2AF1D, 0x4F3D, 0x4C64, { 0x8D, 0x79, 0x9D, 0x36, 0x48, 0x86, 0xFA, 0xF9 } },
  { 0x2944D265, 0x8BB8, 0x497F, { 0xA0, 0xD5, 0xF0, 0x71, 0x9C, 0x2B, 0x42, 0x54 } },
  { 0x90AD9D8A, 0x7CC0, 0x4AF7, { 0x8D, 0xA5, 0x17, 0x58, 0x06, 0x8A, 0x90, 0x0E } },
  { 0xF039C355, 0x0FF2, 0x4FF1, { 0x99, 0x6F, 0x00, 0x6D, 0x6C, 0x5D, 0x67, 0x5E } },
  { 0x0FE2DC2A, 0x973B, 0x4C2B, { 0xB5, 0xB0, 0xBB, 0xCB, 0x83, 0xB1, 0x3B, 0x37 } },
  { 0xB06C3701, 0xFD48, 0x486D, { 0x91, 0x17, 0xE0, 0x37, 0x32, 0x3E, 0x0E, 0xEB } },
  { 0x0945D4C3, 0xC1F7, 0x40D3, { 0xAA, 0x6E, 0x75, 0xDC, 0xD2, 0x45, 0xC7, 0xB1 } },
  { 0x4B39D7E1, 0xB150, 0x4D89, { 0x94, 0xAD, 0xF5, 0x64, 0x53, 0xDE, 0x79, 0x10 } },
  { 0x649FA640, 0xEA1D, 0x4BB5, { 0x82, 0x91, 0x33, 0x1A, 0xCD, 0xDC, 0xBD, 0x5E } },
  { 0xC8360F3E, 0xD55D, 0x4411, { 0xB3, 0x7B, 0x62, 0x00, 0xA1, 0xF0, 0x5F, 0x06 } },
  { 0x14804CC7, 0x26B6, 0x4F19, { 0x81, 0x94, 0xDB, 0xE2, 0xD2, 0x6F, 0x4F, 0xF5 } },
  { 0xE473E2F9, 0x5F45, 0x4C6B, { 0xB4, 0x1D, 0xAE, 0xFA, 0xAA, 0x47, 0x8A, 0x6F } },
  { 0xFCF27D83, 0xC6B9, 0x4CF5, { 0xA7, 0xDA, 0xD4, 0x0C, 0xB3, 0xF4, 0x42, 0xA8 } },
  { 0x8F2C82E1, 0x8B5C, 0x4A05, { 0xAE, 0xC3, 0x7A, 0x72, 0x0B, 0x3E, 0x52, 0x00 } },
  { 0x5699E371, 0x3B04, 0x4E1A, { 0xB4, 0x4F, 0xDF, 0xC7, 0xC0, 0x2A, 0x3E, 0xED } },
  { 0xFE6C0291, 0xD1A4, 0x444A, { 0xA2, 0x9A, 0x98, 0x71, 0xC5, 0x29, 0x9B, 0x96 } },
  { 0x994744CF, 0x2BAE, 0x4127, { 0xB0, 0x3F, 0x03, 0x58, 0x06, 0xB0, 0x9F, 0xAF } },
  { 0x454323E5, 0x908E, 0x4828, { 0xA3, 0x9A, 0x36, 0x69, 0x60, 0x29, 0xF3, 0xF7 } },
  { 0xC100B23B, 0x592D, 0x41BF, { 0xA6, 0xF0, 0xA1, 0x44, 0xD2, 0x7D, 0x5E, 0xF9 } },
  { 0x9F9AF8A8, 0xD98F, 0x4662, { 0xA9, 0x33, 0x8D, 0xFC, 0x9F, 0x84, 0x2E, 0xED } },
  { 0xA8E5AF4A, 0x748C, 0x4C91, { 0xAA, 0x42, 0xC9, 0x69, 0x36, 0x45, 0x6F, 0x88 } },
  { 0x8712431C, 0x2E24, 0x4686, { 0xBF, 0x8A, 0xCA, 0xD4, 0x83, 0x1E, 0x05, 0x8E } },
  { 0xC7C633C4, 0xC33B, 0x490F, { 0xA7, 0x0F, 0x82, 0x4D, 0x87, 0xFC, 0xC3, 0xC1 } },
  { 0xF079C1FE, 0x874C, 0x489C, { 0xA8, 0x2B, 0x3D, 0x09, 0x6E, 0x28, 0x9C, 0xD2 } },
  { 0xC124A0A3, 0x6DAD, 0x4461, { 0xA2, 0xAA, 0x4D, 0x6B, 0x95, 0xB5, 0x52, 0xDB } },
  { 0xDE3D4F80, 0xC4D1, 0x4104, { 0x9F, 0xFE, 0xC4, 0x53, 0x32, 0xA7, 0xE2, 0x68 } },
  { 0xF61363B6, 0x43B2, 0x4ADF, { 0x81, 0xBA, 0x4F, 0x53, 0x4A, 0x6F, 0x7C, 0xEB } },
  { 0xD1E06FB9, 0xBB27, 0x47B3, { 0x9A, 0x8D, 0x16, 0x00, 0xC8, 0xE2, 0xE8, 0xB6 } },
  { 0x02512394, 0x3B8E, 0x4C8C, { 0xB2, 0x5F, 0x14, 0x0B, 0x39, 0xB5, 0xDA, 0xCC } },
  { 0xE864EF21, 0x90C0, 0x428B, { 0xAA, 0xAA, 0xB4, 0x34, 0x5A, 0xCD, 0x10, 0xCF } },
  { 0x3ECAA62E, 0x02B6, 0x4B9C, { 0x9B, 0xD8, 0x86, 0xB1, 0xE0, 0x69, 0xFA, 0xB5 } },
  { 0xD6B8AE93, 0xF882, 0x47B7, { 0x88, 0x6F, 0x86, 0x84, 0x5D, 0xCF, 0xB5, 0xEA } },
  { 0x74A9FEBA, 0x6A80, 0x4E63, { 0x9B, 0xAA, 0xD2, 0xF8, 0x4B, 0x1E, 0xAB, 0xC7 } },
  { 0xF761BC6C, 0xCC66, 0x404E, { 0x89, 0x93, 0x08, 0xFE, 0x36, 0x8C, 0xCB, 0x5B } },
  { 0x3946FC02, 0x1C7C, 0x42C6, { 0x98, 0x8E, 0x70, 0xB6, 0xFF, 0xB5, 0xED, 0xC3 } },
  { 0x9DC6D9A4, 0xD146, 0x495B, { 0x90, 0xC0, 0x12, 0x53, 0xE7, 0x4A, 0x4D, 0x65 } },
  { 0x32E25C09, 0x2CC7, 0x4FDC, { 0x98, 0x5F, 0xA9, 0xF9, 0x97, 0x7D, 0xD1, 0x00 } },
  { 0xA4B7DF30, 0x21A3, 0x455E, { 0x96, 0x68, 0x87, 0x86, 0x65, 0xDE, 0x58, 0x6B } },
  { 0xF64C77C0, 0x29E4, 0x4182, { 0xBB, 0xB4, 0xEA, 0x8F, 0x53, 0xEB, 0x01, 0x75 } },
  { 0x0A2C977A, 0xA45C, 0x4160, { 0x93, 0x39, 0x40, 0x07, 0xD6, 0x64, 0x43, 0x52 } },
  { 0x7BEE0719, 0x38C4, 0x4FD7, { 0x91, 0x5C, 0xBB, 0x71, 0xA7, 0x6B, 0xB8, 0x2C } },
  { 0xBAB7A67C, 0xD572, 0x43FF, { 0x91, 0xB2, 0x59, 0xB4, 0x92, 0x2C, 0xB5, 0x91 } },
  { 0x1F783C93, 0x9343, 0x4657, { 0xB9, 0xA6, 0x9F, 0x00, 0x6A, 0xAF, 0x60, 0x43 } },
  { 0x4ABCDDDA, 0xAE61, 0x4C7A, { 0xBB, 0x03, 0x02, 0xF6, 0x02, 0x0A, 0x1C, 0xF0 } },
  { 0xF054E38F, 0x7450, 0x4529, { 0x8C, 0x7B, 0x7B, 0xA7, 0xE2, 0x81, 0xEA, 0xBF } },
  { 0x4DED9CE3, 0x15B9, 0x4475, { 0xB8, 0x5B, 0xF6, 0x53, 0xFF, 0xDA, 0x8C, 0xEC } },
  { 0x7225777F, 0x892E, 0x424C, { 0x96, 0xF8, 0x89, 0xB8, 0x12, 0x39, 0x1C, 0x57 } },
  { 0x690D021F, 0x2741, 0x418B, { 0xB3, 0x5A, 0x94, 0x57, 0x19, 0xDE, 0x2A, 0xA3 } },
  { 0x6E1D6E36, 0x1BA8, 0x4E9A, { 0x96, 0x39, 0x23, 0x1D, 0x13, 0xE6, 0x4C, 0xFA } },
  { 0x7B406ACB, 0xC172, 0x4951, { 0xB3, 0x51, 0x5B, 0x0F, 0x2B, 0x76, 0x87, 0x33 } },
  { 0x17B66952, 0x1294, 0x4F02, { 0xA7, 0xC9, 0x1D, 0x3D, 0x8F, 0xDC, 0x95, 0x0A } },
  { 0x10966DC5, 0xD292, 0x403E, { 0x89, 0xAB, 0x3F, 0x86, 0xCD, 0xA1, 0x24, 0x30 } },
  { 0xA35AA4CD, 0x77FA, 0x4406, { 0xA0, 0x65, 0xB3, 0x3C, 0xBB, 0x14, 0xD0, 0x54 } },
  { 0x0BAB26F7, 0x9C96, 0x4BB7, { 0xA5, 0xBB, 0x4C, 0xAD, 0x5A, 0xB3, 0x9B, 0xD9 } },
  { 0x22786121, 0x21AE, 0x40D1, { 0xB1, 0xA8, 0x9A, 0x9B, 0x70, 0xBA, 0x21, 0x5E } },
  { 0x687BBCC4, 0x841D, 0x4810, { 0xB9, 0xC7, 0x39, 0xC9, 0x1D, 0x7C, 0xA0, 0x90 } },
  { 0xA514A724, 0x4A14, 0x4608, { 0x9B, 0x71, 0x22, 0xDF, 0x55, 0xA4, 0x4D, 0x17 } },
  { 0x281432D2, 0x4937, 0x4163, { 0xB5, 0xDF, 0xC9, 0x28, 0x09, 0x6A, 0x46, 0x7F } },
  { 0xD5146097, 0x081A, 0x48D9, { 0xA0, 0xEB, 0x16, 0xC4, 0x1F, 0x2C, 0x0D, 0x13 } },
  { 0xA5C3DFA9, 0xC95E, 0x4863, { 0xA8, 0x84, 0xCC, 0xCE, 0xCC, 0xF7, 0x98, 0xF2 } },
  { 0x06E47D84, 0xAE70, 0x4F28, { 0xA6, 0x9B, 0x0F, 0x60, 0xD5, 0xB9, 0xD1, 0x0E } },
  { 0x15692B1A, 0x8298, 0x4E97, { 0xB8, 0x47, 0xA2, 0xB6, 0xB5, 0xD9, 0x73, 0x1E } },
  { 0x704A8B6A, 0x47D2, 0x4113, { 0x99, 0x7C, 0x19, 0xDC, 0xC6, 0x05, 0xC8, 0x4A } },
  { 0xC30AECC1, 0x877D, 0x4C33, { 0x9D, 0xB0, 0xC0, 0xAC, 0x12, 0x7F, 0x66, 0xE7 } },
  { 0x14A4932C, 0xB0AB, 0x4140, { 0x88, 0x0E, 0xA1, 0x85, 0x38, 0x30, 0xD7, 0xB8 } },
  { 0xAA6106E4, 0x1AA4, 0x4067, { 0x98, 0xC4, 0x95, 0x96, 0xAC, 0x52, 0x0E, 0xE8 } },
  { 0x759E1F76, 0x431B, 0x4434, { 0x98, 0xDB, 0x41, 0xBF, 0x95, 0x08, 0xEF, 0x1A } },
  { 0xDD07A823, 0x5D63, 0x4BB5, { 0x9E, 0xFB, 0x5B, 0x10, 0x31, 0xBC, 0x4A, 0x34 } },
  { 0x11EE7D0C, 0x92BC, 0x4F71, { 0x80, 0x3D, 0x63, 0xCA, 0x14, 0xFC, 0x8F, 0x35 } },
  { 0x4EA0729D, 0xD0FD, 0x4BA3, { 0x8A, 0xFC, 0xBD, 0x4E, 0xEF, 0x2F, 0x79, 0xFD } },
  { 0xD8E4FB19, 0x2F2D, 0x4E57, { 0x99, 0x43, 0x81, 0xD1, 0x0C, 0x16, 0xA7, 0xE4 } },
  { 0x35461A36, 0x2654, 0x45A5, { 0xBF, 0xC3, 0xEA, 0xA8, 0x7A, 0x78, 0xDB, 0x45 } },
  { 0xEF33E1D4, 0xAEBE, 0x40A3, { 0xB2, 0xFA, 0xA7, 0xF3, 0x0E, 0xF9, 0xA1, 0xEB } },
  { 0x3AA8F51F, 0x0B3F, 0x42C2, { 0xB0, 0x93, 0x85, 0xB3, 0x1E, 0xBF, 0xAB, 0x43 } },
  { 0xC1EF0306, 0xC02F, 0x4560, { 0xA4, 0xCA, 0xAE, 0x7B, 0x0D, 0x21, 0x47, 0x3D } },
  { 0xC2D42E68, 0xFE1F, 0x40E6, { 0x94, 0x69, 0xBD, 0xBF, 0xD0, 0x4A, 0xE9, 0x4D } },
  { 0xBC6C0DEA, 0x434B, 0x4152, { 0xAD, 0x97, 0xE8, 0xEF, 0x8A, 0xE0, 0x99, 0xD4 } },
  { 0xB947E64C, 0x8E22, 0x4FEF, { 0x9A, 0x0B, 0x61, 0x06, 0x65, 0x4F, 0x95, 0xD1 } },
  { 0x2B12FF7E, 0x926F, 0x489E, { 0xAC, 0xAC, 0x7B, 0xB0, 0xCA, 0x95, 0x6B, 0x80 } },
  { 0x2F808E8B, 0x1274, 0x476B, { 0x86, 0xCC, 0xF2, 0x57, 0x17, 0x7D, 0xCE, 0xB1 } },
  { 0x7414ADA8, 0x9695, 0x4D1F, { 0xA1, 0x7E, 0x16, 0x1C, 0x74, 0x02, 0xDA, 0x5A } },
  { 0xC7E6C297, 0x653F, 0x4817, { 0xAE, 0xC3, 0x6A, 0x7D, 0xCF, 0x60, 0x90, 0x2B } },
  { 0x96496A7E, 0xB93C, 0x407C, { 0xB9, 0x15, 0x47, 0xB5, 0xBB, 0x6F, 0x1A, 0x9F } },
  { 0x926A3E51, 0x3C60, 0x4A2E, { 0xB2, 0x01, 0x20, 0xC7, 0xB6, 0x6E, 0x77, 0x6D } },
  { 0xB556F634, 0x61EB, 0x4770, { 0xA4, 0xF9, 0xBB, 0x8D, 0xE4, 0x8F, 0x02, 0x7D } },
  { 0x1BB50D0C, 0x8052, 0x410C, { 0x94, 0xEA, 0x77, 0x5D, 0xED, 0x96, 0xF2, 0x05 } },
  { 0xF5B12D1D, 0x2D2A, 0x4BF9, { 0xBF, 0x8B, 0x06, 0x53, 0x84, 0xB6, 0x5E, 0x35 } },
  { 0xBDD327B1, 0xE6DC, 0x4137, { 0xB9, 0x3F, 0x46, 0x19, 0x43, 0x2E, 0x24, 0xDC } },
  { 0x59D1DD48, 0x2F62, 0x43B5, { 0x9C, 0x6F, 0x4B, 0xAB, 0x9B, 0x3A, 0x02, 0xC8 } },
  { 0x50C29661, 0x5976, 0x42E9, { 0xBF, 0xC0, 0x85, 0xEE, 0x5C, 0x91, 0xEE, 0x3B } },
  { 0x95E84938, 0xE516, 0x46E2, { 0xAA, 0xFD, 0x4E, 0xE2, 0x05, 0x56, 0x7C, 0xF1 } },
  { 0xFB5C5ACC, 0x3240, 0x4BC3, { 0xBE, 0x0F, 0x9B, 0x1C, 0x5C, 0xCF, 0x22, 0xC6 } },
  { 0xF1837E97, 0x8DAB, 0x4FFB, { 0x81, 0x79, 0xA3, 0xE8, 0x03, 0x15, 0x26, 0x8D } },
  { 0x5D647535, 0xE5D3, 0x456A, { 0x8B, 0x1F, 0x19, 0x93, 0xC2, 0x58, 0x86, 0x3A } },
  { 0xB83B9189, 0xEBB1, 0x4B96, { 0x89, 0xF4, 0x0F, 0x2A, 0xF4, 0xDE, 0x9B, 0xD5 } },
  { 0x4755A9E1, 0xB080, 0x48BD, { 0x85, 0xEA, 0x34, 0xB8, 0xE5, 0x79, 0x19, 0xBB } },
  { 0xBB9778C5, 0x019F, 0x44B0, { 0x8F, 0x82, 0x33, 0xA9, 0x47, 0xB1, 0x15, 0xD1 } },
  { 0x55800314, 0x1450, 0x4A66, { 0xA8, 0xBE, 0xAB, 0xE6, 0x9C, 0x49, 0x50, 0xB7 } },
  { 0x372F2C4A, 0xBB56, 0x4AA2, { 0xBF, 0x3B, 0x38, 0x4A, 0x96, 0x86, 0x86, 0xF7 } },
  { 0x7117FD87, 0x145C, 0x42B3, { 0xB1, 0xB4, 0x54, 0x84, 0xCC, 0xC0, 0x19, 0xE6 } },
  { 0x60E9B18A, 0x43B8, 0x474E, { 0xB2, 0xCB, 0x61, 0xA3, 0xBA, 0x3B, 0xB4, 0x7F } },
  { 0x667E4D18, 0xF2AF, 0x4A73, { 0x9C, 0x5B, 0xD9, 0xA9, 0x4C, 0x4A, 0xB2, 0x99 } },
  { 0x45E11B02, 0x73E7, 0x4BCC, { 0x99, 0x6C, 0x55, 0x0F, 0xFD, 0x15, 0x31, 0x0D } },
  { 0x885C58FC, 0x3D09, 0x4A25, { 0xA7, 0x5D, 0x1F, 0xE3, 0xC5, 0xA9, 0x9C, 0xAB } },
  { 0x18053BFB, 0x7CDF, 0x4E75, { 0xBC, 0xB0, 0xF1, 0x23, 0x70, 0xD3, 0x18, 0x49 } },
  { 0xA5EF2F9F, 0xE2B8, 0x4BBD, { 0xBE, 0x66, 0xF8, 0xDE, 0x5B, 0xAE, 0x72, 0xB9 } },
  { 0xE8843896, 0xA287, 0x4A0B, { 0x89, 0x7C, 0x55, 0xA8, 0x4F, 0xBA, 0xB2, 0xC2 } },
  { 0xCC7C1A77, 0x1E34, 0x41C5, { 0x85, 0xF0, 0x7E, 0x3F, 0x13, 0x31, 0x96, 0xB2 } },
  { 0xB358BB80, 0xDEE4, 0x4F5B, { 0xA8, 0x20, 0x2A, 0xF7, 0x72, 0x7D, 0x3B, 0x78 } },
  { 0x4A623110, 0x1D3A, 0x49F9, { 0xBB, 0x48, 0xEB, 0xFF, 0x79, 0x40, 0xCB, 0xB8 } },
  { 0x60FEF39C, 0x85A2, 0x4C53, { 0xA9, 0x25, 0xBF, 0x7C, 0x6E, 0x3A, 0x39, 0xBE } },
  { 0x4007FFE9, 0x8883, 0x45D7, { 0x80, 0x2F, 0xD6, 0xFD, 0x3C, 0x94, 0x2F, 0x89 } },
  { 0x7B91B7AF, 0xE50A, 0x4B46, { 0x91, 0x25, 0xA4, 0x8D, 0xC0, 0x86, 0x0D, 0x1A } },
  { 0x3128555C, 0xB7A7, 0x44A6, { 0x8A, 0xF2, 0x1C, 0x7A, 0xED, 0xED, 0x82, 0xC0 } },
  { 0x14F7440E, 0x5271, 0x4AE1, { 0xB4, 0x2B, 0x48, 0x12, 0x1B, 0xB8, 0x95, 0x57 } },
  { 0xA6C2B25B, 0x9DC4, 0x4F61, { 0xAB, 0xFF, 0xF4, 0x73, 0xA8, 0x11, 0xD8, 0x8E } },
  { 0xDEBBDD17, 0xE146, 0x44CD, { 0xAB, 0x9A, 0x7A, 0x2D, 0x3D, 0xD6, 0x78, 0x3A } },
  { 0xEDD178C7, 0xA210, 0x4F7F, { 0xA2, 0xBF, 0xC6, 0x66, 0xB6, 0x16, 0x5D, 0x66 } },
  { 0xE78A6254, 0x92B7, 0x47DA, { 0xB5, 0xD5, 0x18, 0xEE, 0x84, 0xD3, 0xDE, 0xB4 } },
  { 0xF5CA4B72, 0x57BC, 0x42EA, { 0x81, 0x15, 0x9D, 0x60, 0x48, 0x25, 0xEA, 0x78 } },
  { 0xB6887FD1, 0x9EAD, 0x4F9A, { 0x93, 0xCB, 0xE9, 0xB4, 0x0F, 0x9A, 0x92, 0x61 } },
  { 0xDBCDBB41, 0x8AB0, 0x4075, { 0xA8, 0x96, 0x44, 0xC9, 0x9F, 0x4D, 0xD1, 0x46 } },
  { 0x9395404B, 0xF34C, 0x4E9A, { 0x90, 0xA0, 0xD7, 0x8E, 0x66, 0x5A, 0x37, 0x26 } },
  { 0xC4D2099A, 0x1F8F, 0x4DB4, { 0xA0, 0x6D, 0x06, 0xE3, 0x6E, 0xBD, 0x70, 0x66 } },
  { 0xE401E89A, 0x8553, 0x4467, { 0x9D, 0x14, 0xED, 0x6C, 0x01, 0xE0, 0xBF, 0x50 } },
  { 0xD7A7C0E6, 0xE843, 0x48EA, { 0xA1, 0xDF, 0xFA, 0x9B, 0x5C, 0x2D, 0x45, 0xF2 } },
  { 0xD97669DD, 0xF228, 0x43C3, { 0x9A, 0x96, 0x47, 0xAF, 0x51, 0xDD, 0xE4, 0x45 } },
  { 0x452269BB, 0x7C5B, 0x417C, { 0x93, 0xF0, 0x51, 0x31, 0x72, 0x1A, 0x27, 0x39 } },
  { 0x567B1C7A, 0xF782, 0x4D0A, { 0x84, 0xEA, 0x50, 0x99, 0xAE, 0xD8, 0x48, 0xA4 } },
  { 0xFC636755, 0xCDA3, 0x40FC, { 0xB1, 0xF0, 0xA8, 0x11, 0x2A, 0xCA, 0x73, 0xA7 } },
  { 0x4ADCE1E3, 0xD290, 0x44DE, { 0x85, 0x95, 0x6E, 0x60, 0x05, 0x83, 0x0F, 0xDC } },
  { 0x5974DD22, 0x7A6E, 0x46BA, { 0xA2, 0xE4, 0x28, 0x1D, 0x11, 0x36, 0x18, 0xF8 } },
  { 0x602B8735, 0xEDE6, 0x4FBF, { 0xB0, 0x6B, 0x48, 0xE5, 0x1F, 0xC4, 0xDD, 0x25 } },
  { 0x7F9A1D83, 0x4FB3, 0x45CC, { 0x8D, 0x58, 0xE6, 0x86, 0x44, 0x17, 0x86, 0xE8 } },
  { 0x3A21D062, 0xAB47, 0x4744, { 0xB4, 0xF7, 0x08, 0xD0, 0x26, 0x2A, 0x9C, 0x6E } },
  { 0x83C97BC8, 0xB1C6, 0x4046, { 0xA3, 0xDD, 0x50, 0x1B, 0x5A, 0x6F, 0x4F, 0x83 } },
  { 0xBBBA9EAD, 0xFDAD, 0x49D7, { 0x99, 0xDA, 0xF5, 0xC9, 0xD1, 0xD6, 0xFD, 0x0E } },
  { 0xC5A15D64, 0xD285, 0x4753, { 0x87, 0x08, 0x8B, 0x18, 0x7C, 0xFA, 0x99, 0xD1 } },
  { 0xAEA99E2F, 0xC760, 0x4314, { 0x96, 0xF2, 0x89, 0xBE, 0xD2, 0x2D, 0xCB, 0x9C } },
  { 0x2D6B4179, 0x99C3, 0x4FD1, { 0x9F, 0x37, 0xB5, 0xAE, 0x7C, 0x2D, 0xC1, 0x65 } },
  { 0x0E7631BF, 0x24D6, 0x48A3, { 0xB4, 0xDD, 0xE5, 0xCE, 0x8C, 0x75, 0x73, 0xEF } },
  { 0x34F818B5, 0x0D80, 0x494C, { 0xAF, 0x63, 0x78, 0x58, 0x0C, 0xED, 0xE7, 0x3E } },
  { 0xC073CAEC, 0xB964, 0x4FBF, { 0x8D, 0x0A, 0x0E, 0x10, 0x77, 0x48, 0x6B, 0x61 } },
  { 0x8FDFAF32, 0x1A88, 0x41AC, { 0x9D, 0x67, 0xFC, 0x55, 0x70, 0x84, 0x7E, 0xD9 } },
  { 0x00017E92, 0x8DF8, 0x40B2, { 0x93, 0xA5, 0xB6, 0x46, 0x1A, 0x10, 0x0E, 0xCE } },
  { 0xAD1612B1, 0xC034, 0x494E, { 0x8B, 0xB7, 0xA8, 0x16, 0xE8, 0x1F, 0xFA, 0x80 } },
  { 0x75389456, 0x0905, 0x47DB, { 0x90, 0x95, 0x54, 0x3B, 0xBD, 0x8A, 0x9A, 0x43 } },
  { 0x617ED5AD, 0x0CA8, 0x402E, { 0x98, 0x2D, 0xB3, 0xEA, 0xBC, 0x2A, 0xFC, 0x6A } },
  { 0xCEF27E08, 0x0C81, 0x41C3, { 0x99, 0x34, 0xB6, 0xE0, 0xF1, 0x3E, 0x66, 0xE0 } },
  { 0xBF9DB8A8, 0x589B, 0x4FED, { 0x94, 0xB1, 0x19, 0x6F, 0xF7, 0xD7, 0xC2, 0xE0 } },
  { 0xA10AD389, 0xF63B, 0x40F2, { 0x90, 0x78, 0x0E, 0xEA, 0xE6, 0xB8, 0xA2, 0x8B } },
  { 0xDA3D3279, 0x6F08, 0x4DDE, { 0x9A, 0x83, 0x7F, 0x90, 0x51, 0x1A, 0xB4, 0xCD } },
  { 0x10657E5F, 0x0F16, 0x40CF, { 0xAA, 0x15, 0x75, 0x4C, 0xF7, 0xD7, 0x61, 0x15 } },
  { 0xF736380B, 0xE636, 0x4BB7, { 0xB3, 0x3F, 0xF5, 0x50, 0x17, 0xFB, 0x51, 0x69 } },
  { 0xCBB0A799, 0x46DD, 0x4A28, { 0x9F, 0x75, 0xBE, 0x1B, 0xD8, 0x02, 0x0E, 0x51 } },
  { 0xF7400C4F, 0xDDDF, 0x4A45, { 0x87, 0x95, 0x4A, 0xAB, 0xBB, 0x21, 0x3C, 0x45 } },
  { 0xACE3A5D4, 0xEC85, 0x4F90, { 0xA8, 0x67, 0xBF, 0xCE, 0x91, 0x4C, 0x40, 0x81 } },
  { 0x50AC0E69, 0xA42A, 0x4B77, { 0xA3, 0x58, 0x81, 0x0F, 0x31, 0xB5, 0xD0, 0x18 } },
  { 0x3C8402EB, 0xF94E, 0x4500, { 0xA3, 0x97, 0xF1, 0x57, 0xBE, 0xCB, 0x41, 0x88 } },
  { 0x3F5AB60E, 0xC793, 0x4851, { 0x95, 0x24, 0x0E, 0x4A, 0x53, 0x0D, 0xEF, 0xD2 } },
  { 0xBC33F26E, 0x686B, 0x4B03, { 0xB8, 0x0F, 0x9E, 0x74, 0x1D, 0x78, 0xD5, 0x2D } },
  { 0x56ED167F, 0x7D16, 0x4DF4, { 0xBC, 0xFA, 0x62, 0x4A, 0x3B, 0x00, 0x73, 0x86 } },
  { 0x585CCE90, 0x7E73, 0x447F, { 0xBF, 0x62, 0x12, 0x4A, 0x42, 0x70, 0x24, 0x3C } },
  { 0xC0CC3AF3, 0xC86C, 0x4026, { 0x8A, 0xB2, 0x09, 0x3E, 0xDB, 0x3A, 0xD8, 0xC0 } },
  { 0xAFBDE234, 0x434B, 0x4E62, { 0xB8, 0x0C, 0xE7, 0x5C, 0x96, 0x84, 0x7C, 0x1B } },
  { 0xDA6C9618, 0x627E, 0x4A61, { 0x9B, 0x08, 0x6A, 0x20, 0xBD, 0xE5, 0xBB, 0xDF } },
  { 0xFE234E02, 0x2F66, 0x4D29, { 0x84, 0xF8, 0xF7, 0x16, 0xC2, 0xB6, 0x4B, 0x0E } },
  { 0x50947096, 0xDF9A, 0x4A8A, { 0xB3, 0x9B, 0xAC, 0xF7, 0x66, 0x38, 0xFD, 0x6B } },
  { 0x7AA7F7F7, 0xD62B, 0x4BF1, { 0x96, 0x0A, 0xC0, 0xCA, 0x86, 0x8A, 0xF0, 0x89 } },
  { 0x3D799374, 0xC878, 0x48A2, { 0x86, 0x18, 0xD8, 0x23, 0x93, 0x24, 0x82, 0x34 } },
  { 0x885F25D0, 0x2799, 0x421C, { 0xAB, 0x5B, 0x42, 0x5E, 0x1A, 0x7E, 0x15, 0x7A } },
  { 0xEBFF1AB6, 0xAAFE, 0x45CE, { 0x88, 0xEA, 0x5D, 0x2B, 0x30, 0x75, 0x88, 0x09 } },
  { 0xFA5545E9, 0x825B, 0x4BCF, { 0x90, 0xBB, 0xD0, 0x5D, 0xAC, 0x8F, 0xA7, 0xB7 } },
  { 0x5439A2DC, 0x13C4, 0x45B8, { 0xB7, 0x1A, 0x5B, 0xFE, 0x14, 0x6F, 0x8B, 0xAB } },
  { 0x81E13157, 0x77BF, 0x49E1, { 0xBC, 0xC1, 0xB1, 0x01, 0x3A, 0xC1, 0xFE, 0xCD } },
  { 0x1167E2FD, 0x6399, 0x448C, { 0xB0, 0x20, 0x43, 0xC6, 0x3F, 0x94, 0x69, 0x47 } },
  { 0x6699674A, 0xBC7B, 0x4BF9, { 0x9C, 0x23, 0x73, 0x8B, 0x63, 0xCE, 0x3F, 0xCC } },
  { 0xF970A0A1, 0x8DCC, 0x46F1, { 0x86, 0xD8, 0x16, 0x4A, 0x45, 0xF2, 0x27, 0x5F } },
  { 0x128BF906, 0x9CD0, 0x4955, { 0x9B, 0x23, 0xD3, 0x53, 0x46, 0x4B, 0x4F, 0x1D } },
  { 0x97749637, 0x0598, 0x4621, { 0xB1, 0xA8, 0xBC, 0x2E, 0x40, 0x2B, 0xC0, 0x5C } },
  { 0xBDE356AB, 0x1EE9, 0x4819, { 0x90, 0x18, 0xF9, 0xD4, 0x10, 0x76, 0xF4, 0xF3 } },
  { 0x3C23EE92, 0x7206, 0x4BC8, { 0xAC, 0xB8, 0x06, 0x9D, 0x9E, 0xE0, 0xC7, 0x3A } },
  { 0xF3FED715, 0xA68C, 0x40DD, { 0xA2, 0x3E, 0xBE, 0x92, 0x41, 0xF0, 0xC2, 0xC6 } },
  { 0x87734F81, 0x9B91, 0x4BC3, { 0xAA, 0x05, 0x61, 0x45, 0xB5, 0x3D, 0xD7, 0xA7 } },
  { 0x8A40DC28, 0x1E56, 0x4BE1, { 0xB6, 0x8E, 0x3C, 0x4D, 0x54, 0xC1, 0xFB, 0x67 } },
  { 0x01883267, 0x8AE5, 0x4564, { 0xBF, 0x0D, 0x38, 0xEB, 0xBD, 0x95, 0xB6, 0xD4 } },
  { 0x4E1B4335, 0xA933, 0x45D4, { 0x9A, 0xBC, 0x0B, 0xFF, 0x95, 0xF1, 0xFB, 0xA2 } },
  { 0x5EFE04EB, 0xB8A5, 0x4B11, { 0x98, 0xC9, 0x13, 0x58, 0xB0, 0x6E, 0xFD, 0x9D } },
  { 0x1FC7D1F6, 0xBB0C, 0x4AB6, { 0xAC, 0x62, 0x61, 0x01, 0x0C, 0xF8, 0xDC, 0xF1 } },
  { 0xF8BA6AE4, 0xBC1C, 0x44A7, { 0xB1, 0x19, 0x29, 0x22, 0x63, 0x5E, 0x51, 0x8C } },
  { 0x714EBEF7, 0xCD19, 0x4815, { 0xAE, 0xB8, 0x91, 0x25, 0xFF, 0x3A, 0xF4, 0x7F } },
};
UINTN NumGuidInUse = 0;


extern VOID *HandlerContext;
extern BOOLEAN IsRootHandler;
EFI_STATUS EFIAPI RegisterSmmDispatchHandler(
  IN  VOID *This,
  IN  VOID *DispatchFunction,
  IN  VOID *RegisterContext,
  OUT EFI_HANDLE *Handler,
  UINTN ContextSize
) {
  EFI_HANDLE Handle = NULL;
  IsRootHandler = TRUE;
  HandlerContext = (VOID*) 0xb000000000000000;
  EFI_STATUS Status = SmiHandlerRegister(
                DispatchFunction,
               &RootHandlerGuids[NumGuidInUse++],
               &Handle
               );
  HandlerContext = NULL;
  IsRootHandler = FALSE;
  return Status;
}
EFI_STATUS EFIAPI UnRegisterSmmDispatchHandler(
  IN CONST VOID    *This,
  IN       EFI_HANDLE                      DispatchHandle
) {
  return EFI_SUCCESS;
}
typedef struct _SMM_ROOT_SMI_DISPATCH {
  VOID *Register;
  VOID *UnRegister;
}SMM_ROOT_SMI_DISPATCH;

SMM_ROOT_SMI_DISPATCH SmmRootSmiDispatch;

EFI_STATUS InstallSmmFuzzSmiHandler(VOID)
{
  EFI_HANDLE Handle = NULL;
  EFI_STATUS Status = SmiHandlerRegister(
               SmmReportHandler,
               &gEfiSmmReportSmmModuleInfoGuid,
               &Handle
               );
  Handle = NULL;
  Status = SmiHandlerRegister(
               SmmFuzzRootHandler,
               &gEfiSmmFuzzRootGuid,
               &Handle
               );

  GUID DispatchHandlerGuids[] = {
    // EFI_SMM_SW_DISPATCH2_PROTOCOL_GUID
    { 
      0x18a3c6dc, 0x5eea, 0x48c8, {0xa1, 0xc1, 0xb5, 0x33, 0x89, 0xf9, 0x89, 0x99}},
    // EFI_SMM_SW_DISPATCH_PROTOCOL_GUID
    { 
      0xe541b773, 0xdd11, 0x420c, {0xb0, 0x26, 0xdf, 0x99, 0x36, 0x53, 0xf8, 0xbf}},
    // EFI_SMM_SX_DISPATCH2_PROTOCOL_GUID
    { 
      0x456d2859, 0xa84b, 0x4e47, {0xa2, 0xee, 0x32, 0x76, 0xd8, 0x86, 0x99, 0x7d}},
    // EFI_SMM_SX_DISPATCH_PROTOCOL_GUID
    {
      0x14FC52BE, 0x01DC, 0x426C, {0x91, 0xAE, 0xA2, 0x3C, 0x3E, 0x22, 0x0A, 0xE8}},
    // EFI_SMM_IO_TRAP_DISPATCH2_PROTOCOL_GUID
    {
      0x58DC368D, 0x7BFA, 0x4E77, {0xAB, 0xBC, 0x0E, 0x29, 0x41, 0x8D, 0xF9, 0x30}},
    // EFI_SMM_IO_TRAP_DISPATCH_PROTOCOL_GUID
    {
      0xDB7F536B, 0xEDE4, 0x4714, {0xA5, 0xC8, 0xE3, 0x46, 0xEB, 0xAA, 0x20, 0x1D}},
    // EFI_SMM_GPI_DISPATCH2_PROTOCOL_GUID
    {
      0x25566B03, 0xB577, 0x4CBF, {0x95, 0x8C, 0xED, 0x66, 0x3E, 0xA2, 0x43, 0x80}},
    // EFI_SMM_GPI_DISPATCH_PROTOCOL_GUID
    {
      0xE0744B81, 0x9513, 0x49CD, {0x8C, 0xEA, 0xE9, 0x24, 0x5E, 0x70, 0x39, 0xDA}},
    // EFI_SMM_USB_DISPATCH2_PROTOCOL_GUID
    {
        0xEE9B8D90, 0xC5A6, 0x40A2, {0xBD, 0xE2, 0x52, 0x55, 0x8D, 0x33, 0xCC, 0xA1}},
    // EFI_SMM_USB_DISPATCH_PROTOCOL_GUID
    {
        0xA05B6FFD, 0x87AF, 0x4E42, {0x95, 0xC9, 0x62, 0x28, 0xB6, 0x3C, 0xF3, 0xF3}},
    // EFI_SMM_STANDBY_BUTTON_DISPATCH2_PROTOCOL_GUID
    {
        0x7300C4A1, 0x43F2, 0x4017, {0xA5, 0x1B, 0xC8, 0x1A, 0x7F, 0x40, 0x58, 0x5B}},
    // EFI_SMM_STANDBY_BUTTON_DISPATCH_PROTOCOL_GUID
    {
        0x78965B98, 0xB0BF, 0x449E, {0x8B, 0x22, 0xD2, 0x91, 0x4E, 0x49, 0x8A, 0x98}},
    // EFI_SMM_PERIODIC_TIMER_DISPATCH2_PROTOCOL_GUID
    {
        0x4CEC368E, 0x8E8E, 0x4D71, {0x8B, 0xE1, 0x95, 0x8C, 0x45, 0xFC, 0x8A, 0x53}},
    // EFI_SMM_PERIODIC_TIMER_DISPATCH_PROTOCOL_GUID
    {
        0x9CCA03FC, 0x4C9E, 0x4A19, {0x9B, 0x06, 0xED, 0x7B, 0x47, 0x9B, 0xDE, 0x55}},
    // EFI_SMM_POWER_BUTTON_DISPATCH2_PROTOCOL_GUID
    {
        0x1B1183FA, 0x1823, 0x46A7, {0x88, 0x72, 0x9C, 0x57, 0x87, 0x55, 0x40, 0x9D}},
    // EFI_SMM_POWER_BUTTON_DISPATCH_PROTOCOL_GUID
    {
        0xB709EFA0, 0x47A6, 0x4B41, {0xB9, 0x31, 0x12, 0xEC, 0xE7, 0xA8, 0xEE, 0x56}},
  };

  SmmRootSmiDispatch.Register = RegisterSmmDispatchHandler;
  SmmRootSmiDispatch.UnRegister = UnRegisterSmmDispatchHandler;
  for (UINTN i = 0; i < ( sizeof(DispatchHandlerGuids) / sizeof(DispatchHandlerGuids[0])) ; i++)
  {
    Handle = NULL;
    Status = SmmInstallProtocolInterface (
                &Handle,
                &DispatchHandlerGuids[i],
                EFI_NATIVE_INTERFACE,
                &SmmRootSmiDispatch
                );
    ASSERT_EFI_ERROR (Status);
  }
  return Status;
}

// extern LIST_ENTRY  mSmiEntryList;
extern LIST_ENTRY  mDiscoveredList;
extern EFI_SMRAM_DESCRIPTOR  *mSmmMemLibInternalSmramRanges;
extern UINTN                 mSmmMemLibInternalSmramCount;
UINT8 Test;
SMM_MODULES_HANDLER_PROTOCOL_INFO SmmModulesHandlerProtocolInfo = {0};
GUID CurrentModule = {0};
EFI_STATUS
EFIAPI
SmmReportHandler (
  IN     EFI_HANDLE  DispatchHandle,
  IN     CONST VOID  *Context         OPTIONAL,
  IN OUT VOID        *CommBuffer      OPTIONAL,
  IN OUT UINTN       *CommBufferSize  OPTIONAL
  )
{
  LIST_ENTRY  *Link;
  EFI_SMM_DRIVER_ENTRY  *DriverEntry;
  SMM_MODULES_HANDLER_PROTOCOL_INFO_ADDR *data = (SMM_MODULES_HANDLER_PROTOCOL_INFO_ADDR*)CommBuffer;
  EFI_PHYSICAL_ADDRESS    PhysicalStartBegin, PhysicalStartEnd;
  EFI_PHYSICAL_ADDRESS    CpuStartBegin, CpuStartEnd;
  UINT64                  PhysicalSizeEnd;

  if (mSmmMemLibInternalSmramCount > 0) {
    PhysicalStartBegin = PhysicalStartEnd = mSmmMemLibInternalSmramRanges[0].PhysicalStart;
    CpuStartBegin = CpuStartEnd = mSmmMemLibInternalSmramRanges[0].CpuStart;
    PhysicalSizeEnd = mSmmMemLibInternalSmramRanges[0].PhysicalSize;
    for (UINTN Index = 1; Index < mSmmMemLibInternalSmramCount; Index++) {
      if (mSmmMemLibInternalSmramRanges[Index].PhysicalStart <= PhysicalStartBegin) {
        PhysicalStartBegin = mSmmMemLibInternalSmramRanges[Index].PhysicalStart;
        CpuStartBegin =  mSmmMemLibInternalSmramRanges[Index].CpuStart;
      }
      else if (mSmmMemLibInternalSmramRanges[Index].PhysicalStart > PhysicalStartEnd){
        PhysicalStartEnd = mSmmMemLibInternalSmramRanges[Index].PhysicalStart;
        CpuStartEnd = mSmmMemLibInternalSmramRanges[Index].CpuStart;
        PhysicalSizeEnd = mSmmMemLibInternalSmramRanges[Index].PhysicalSize;
      }
    }
  }
  else {
    PhysicalStartBegin = PhysicalStartEnd = CpuStartEnd = CpuStartBegin = PhysicalSizeEnd = 0;
  }
  
  SmmModulesHandlerProtocolInfo.PhysicalSize = PhysicalStartEnd + PhysicalSizeEnd - PhysicalStartBegin;
  SmmModulesHandlerProtocolInfo.CpuStart = CpuStartBegin;
  SmmModulesHandlerProtocolInfo.PhysicalStart = PhysicalStartBegin;
  SmmModulesHandlerProtocolInfo.DummyAddr = &SmmFuzzDummyMemory;
  VOID* RedZonePageAddr;
  SmmAllocatePool(EfiRuntimeServicesData,1,&RedZonePageAddr);
  SmmModulesHandlerProtocolInfo.RedZonePageAddr = RedZonePageAddr + 8;
  for (Link = mDiscoveredList.ForwardLink; Link != &mDiscoveredList; Link = Link->ForwardLink) {
    DriverEntry = CR (Link, EFI_SMM_DRIVER_ENTRY, Link, EFI_SMM_DRIVER_ENTRY_SIGNATURE);
    if (DriverEntry->Dependent) {
      InsertUnloadModule(&DriverEntry->FileName);
    }
  }
  CopyMem(data->addr,&SmmModulesHandlerProtocolInfo, sizeof(SmmModulesHandlerProtocolInfo));
  // LIBAFL_QEMU_SMM_HELP_COPY((UINT64)data->addr, (UINT64)&SmmModulesHandlerProtocolInfo, (UINT64)sizeof(SmmModulesHandlerProtocolInfo));
  NoCommbufCheck = TRUE;
  return EFI_SUCCESS;
}
EFI_STATUS
EFIAPI
SmmFuzzRootHandler (
  IN     EFI_HANDLE  DispatchHandle,
  IN     CONST VOID  *Context         OPTIONAL,
  IN OUT VOID        *CommBuffer      OPTIONAL,
  IN OUT UINTN       *CommBufferSize  OPTIONAL
  )
{
  DEBUG((DEBUG_INFO,"SmmFuzzRootHandler enter\n"));
  SmiManage (NULL, NULL, NULL, NULL);
  return EFI_SUCCESS;
}



VOID InsertNewSmmModule(GUID *Guid, VOID *Addr, UINT64 Size)
{
  for (UINTN i = 0; i < SmmModulesHandlerProtocolInfo.NumModules; i++)
  {
    if (CompareGuid(Guid, &SmmModulesHandlerProtocolInfo.info[i].Guid))
    {
      return;
    }
  }
  if (SmmModulesHandlerProtocolInfo.NumModules >= MAX_NUM_MODULES)
    return;
  CopyGuid(&SmmModulesHandlerProtocolInfo.info[SmmModulesHandlerProtocolInfo.NumModules].Guid, Guid);
  SmmModulesHandlerProtocolInfo.info[SmmModulesHandlerProtocolInfo.NumModules].ImageBase = Addr;
  SmmModulesHandlerProtocolInfo.info[SmmModulesHandlerProtocolInfo.NumModules].ImageSize = Size;
  SmmModulesHandlerProtocolInfo.NumModules++;
}
VOID InsertSmiHandler(CONST GUID *Handler, BOOLEAN IsRoot)
{
  if (Handler == NULL)
  {
    return InsertRootSmiHandler();
  }
  for (UINTN i = 0; i < SmmModulesHandlerProtocolInfo.NumModules; i++)
  {
    if (!CompareGuid(&CurrentModule, &SmmModulesHandlerProtocolInfo.info[i].Guid))
    {
      continue;
    }
    for (UINTN j = 0; j < SmmModulesHandlerProtocolInfo.info[i].NumSmiHandlers; j++)
    {
      if (CompareGuid(Handler, &SmmModulesHandlerProtocolInfo.info[i].SmiHandlers[j].SmiHandler))
      {
        return;
      }
    }
    if (SmmModulesHandlerProtocolInfo.info[i].NumSmiHandlers >= MAX_NUM_HANDLERS)
      return;
    SmmModulesHandlerProtocolInfo.info[i].SmiHandlers[SmmModulesHandlerProtocolInfo.info[i].NumSmiHandlers].IsRoot = IsRoot;
    CopyGuid(&SmmModulesHandlerProtocolInfo.info[i].SmiHandlers[SmmModulesHandlerProtocolInfo.info[i].NumSmiHandlers++].SmiHandler, Handler);
    
    return;
  }
}
VOID InsertRootSmiHandler(VOID)
{
  SmmModulesHandlerProtocolInfo.NumRootSmiHandlers++;
}
VOID InsertProduceProtocol(CONST GUID *Protocol)
{
  if (Protocol == NULL)
    return;
  for (UINTN i = 0; i < SmmModulesHandlerProtocolInfo.NumModules; i++)
  {
    if (!CompareGuid(&CurrentModule, &SmmModulesHandlerProtocolInfo.info[i].Guid))
    {
      continue;
    }
    UINTN NumProtocol = SmmModulesHandlerProtocolInfo.info[i].NumProduceProtocols;
    BOOLEAN Found = FALSE;
    for (UINTN j = 0; j < NumProtocol; j++)
    {
      if (CompareGuid(&SmmModulesHandlerProtocolInfo.info[i].ProduceProtocols[j], Protocol))
      {
        Found = TRUE;
        break;
      }
    }
    if (!Found && NumProtocol < MAX_NUM_PRODUCE_PROTOCOLS)
    {
      CopyGuid(&SmmModulesHandlerProtocolInfo.info[i].ProduceProtocols[NumProtocol], Protocol);
      SmmModulesHandlerProtocolInfo.info[i].NumProduceProtocols ++;
    }
    return;
  }
}
VOID InsertConsumeProtocol(CONST GUID *Protocol)
{
  if (Protocol == NULL)
    return;
  for (UINTN i = 0; i < SmmModulesHandlerProtocolInfo.NumModules; i++)
  {
    if (!CompareGuid(&CurrentModule, &SmmModulesHandlerProtocolInfo.info[i].Guid))
    {
      continue;
    }
    UINTN NumProtocol = SmmModulesHandlerProtocolInfo.info[i].NumConsumeProtocols;
    BOOLEAN Found = FALSE;
    for (UINTN j = 0; j < NumProtocol; j++)
    {
      if (CompareGuid(&SmmModulesHandlerProtocolInfo.info[i].ConsumeProtocols[j], Protocol))
      {
        Found = TRUE;
        break;
      }
    }
    if (!Found && NumProtocol < MAX_NUM_CONSUME_PROTOCOLS)
    {
      CopyGuid(&SmmModulesHandlerProtocolInfo.info[i].ConsumeProtocols[NumProtocol], Protocol);
      SmmModulesHandlerProtocolInfo.info[i].NumConsumeProtocols ++;
    }
  }
}
VOID ClearCurrentModule(VOID)
{
  ZeroMem(&CurrentModule,sizeof(GUID));
}
VOID SetCurrentModule(CONST GUID *guid)
{
  if (guid == NULL) {
    ClearCurrentModule();
    return;
  }   
  CopyGuid(&CurrentModule, guid);
}
VOID SetCurrentModuleBySmi(CONST GUID *guid)
{
  if (guid == NULL)
  {
    ClearCurrentModule();
    return;
  }  
  for (UINTN i = 0; i < SmmModulesHandlerProtocolInfo.NumModules; i++)
  {
    for (UINTN j = 0; j < SmmModulesHandlerProtocolInfo.info[i].NumSmiHandlers; j++)
    {
      if (CompareGuid(&SmmModulesHandlerProtocolInfo.info[i].SmiHandlers[j].SmiHandler, guid))
      {
        SetCurrentModule(&SmmModulesHandlerProtocolInfo.info[i].Guid);
        return;
      }
    }
  }
  ClearCurrentModule();
}
VOID InsertUnloadModule(GUID *guid)
{
  for (UINTN i = 0; i < SmmModulesHandlerProtocolInfo.NumUnloadModules; i++)
  {
    if (CompareGuid(&SmmModulesHandlerProtocolInfo.UnloadModules[i], guid))
      {
        return;
      }
  }
  if (SmmModulesHandlerProtocolInfo.NumUnloadModules >= MAX_NUM_NONLOADED_MODULES)
    return;
  CopyGuid(&SmmModulesHandlerProtocolInfo.UnloadModules[SmmModulesHandlerProtocolInfo.NumUnloadModules++], guid);
}
VOID InsertSkipModule(GUID *guid)
{
  for (UINTN i = 0; i < SmmModulesHandlerProtocolInfo.NumSkipModules; i++)
  {
    if (CompareGuid(&SmmModulesHandlerProtocolInfo.SkipModules[i], guid))
      {
        return;
      }
  }
  if (SmmModulesHandlerProtocolInfo.NumSkipModules >= MAX_NUM_SKIP_MODULES)
    return;
  CopyGuid(&SmmModulesHandlerProtocolInfo.SkipModules[SmmModulesHandlerProtocolInfo.NumSkipModules++], guid);
}
VOID RemoveSkipModule(GUID *guid)
{
  UINTN Index = -1;
  for (UINTN i = 0; i < SmmModulesHandlerProtocolInfo.NumSkipModules; i++)
  {
    if (CompareGuid(&SmmModulesHandlerProtocolInfo.SkipModules[i], guid))
    {
      Index = i;
      break;
    }
  }
  if (Index == -1)
    return;
  CopyMem(&SmmModulesHandlerProtocolInfo.SkipModules[Index], &SmmModulesHandlerProtocolInfo.SkipModules[Index + 1], sizeof(GUID) * (SmmModulesHandlerProtocolInfo.NumSkipModules - Index -1));
  SmmModulesHandlerProtocolInfo.NumSkipModules--;
}