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
extern SMM_FUZZ_GLOBAL_DATA *SmmFuzzGlobalData;
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
  DEBUG((DEBUG_INFO,"SmmReadyToLockHandler start\n"));

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
  SmmHandle = NULL;
  Status    = SmmInstallProtocolInterface (
                &SmmHandle,
                &gEfiSmmReadyToLockProtocolGuid,
                EFI_NATIVE_INTERFACE,
                NULL
                );

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

  DEBUG ((DEBUG_INFO, "SmmEndOfDxeHandler\n"));

  PERF_CALLBACK_BEGIN (&gEfiEndOfDxeEventGroupGuid);

  //
  // Install SMM EndOfDxe protocol
  //
  SmmHandle = NULL;
  Status    = SmmInstallProtocolInterface (
                &SmmHandle,
                &gEfiSmmEndOfDxeProtocolGuid,
                EFI_NATIVE_INTERFACE,
                NULL
                );

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
  gSmmCoreSmst.SmmStartupThisAp      = SmmEntryContext->SmmStartupThisAp;
  gSmmCoreSmst.CurrentlyExecutingCpu = SmmEntryContext->CurrentlyExecutingCpu;
  gSmmCoreSmst.NumberOfCpus          = SmmEntryContext->NumberOfCpus;
  gSmmCoreSmst.CpuSaveStateSize      = SmmEntryContext->CpuSaveStateSize;
  gSmmCoreSmst.CpuSaveState          = SmmEntryContext->CpuSaveState;

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

      if (!SmmIsBufferOutsideSmmValid ((UINTN)CommunicationBuffer, BufferSize) ||
          IsOverlapped || IsOverUnderflow)
      {
        //
        // If CommunicationBuffer is not in valid address scope,
        // or there is overlap between gSmmCorePrivate and CommunicationBuffer,
        // or there is over or underflow,
        // return EFI_INVALID_PARAMETER
        //
        gSmmCorePrivate->CommunicationBuffer = NULL;
        gSmmCorePrivate->ReturnStatus        = EFI_ACCESS_DENIED;
      } else {
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
  SmiManage (NULL, NULL, NULL, NULL);

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
  if(!gST) {
    SmmEntryPoint(SmmEntryContext); 
    return;
  }
    
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

  GUID SMMCORE_GUID = {0xE94F54CD, 0x81EB, 0x47ed, {0xAE, 0xC3, 0x85, 0x6F, 0x5D, 0xC1, 0x57, 0xA9}};
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
      if (CompareGuid(&NameGuid, &SMMCORE_GUID)) {
          EFI_SMM_DRIVER_ENTRY  *DriverEntry;
          DriverEntry = AllocateZeroPool (sizeof (EFI_SMM_DRIVER_ENTRY));
          ASSERT (DriverEntry != NULL);
          DriverEntry->Signature = EFI_SMM_DRIVER_ENTRY_SIGNATURE;
          CopyGuid (&DriverEntry->FileName, &NameGuid);
          DriverEntry->FvHandle         = FvHandle;
          DriverEntry->Fv               = Fv;
          DriverEntry->FvFileDevicePath = SmmFvToDevicePath (Fv, FvHandle, &NameGuid);
          Status = SmmLoadImage (DriverEntry);
          ASSERT_EFI_ERROR (Status);

          EFI_SMRAM_DESCRIPTOR *OldSmramRange;
          EFI_SMRAM_DESCRIPTOR *TmpSmramRange;
          Status = gBS->AllocatePool (EfiBootServicesData, gSmmCorePrivate->SmramRangeCount * sizeof(EFI_SMRAM_DESCRIPTOR), (VOID **)&TmpSmramRange);
          ASSERT_EFI_ERROR (Status);
          CopyMem(TmpSmramRange, gSmmCorePrivate->SmramRanges, gSmmCorePrivate->SmramRangeCount * sizeof(EFI_SMRAM_DESCRIPTOR));
          OldSmramRange = gSmmCorePrivate->SmramRanges;
          gSmmCorePrivate->SmramRanges = TmpSmramRange;
          for (UINTN i = 0 ; i < gSmmCorePrivate->SmramRangeCount; i++)
          {
            // DEBUG((DEBUG_INFO,"smram  %p %p %x %x\n",gSmmCorePrivate->SmramRanges[i].CpuStart, gSmmCorePrivate->SmramRanges[i].PhysicalStart, gSmmCorePrivate->SmramRanges[i].PhysicalSize, gSmmCorePrivate->SmramRanges[i].RegionState));
            if ((gSmmCorePrivate->SmramRanges[i].RegionState & (EFI_ALLOCATED | EFI_NEEDS_TESTING | EFI_NEEDS_ECC_INITIALIZATION)) != 0) {
              continue;
            }
            gSmmCorePrivate->SmramRanges[i].CpuStart += gSmmCorePrivate->SmramRanges[i].PhysicalSize;
            gSmmCorePrivate->SmramRanges[i].PhysicalStart += gSmmCorePrivate->SmramRanges[i].PhysicalSize;
            gSmmCorePrivate->SmramRanges[i].PhysicalSize = 0x100000;
          }
          LIBAFL_QEMU_END(LIBAFL_QEMU_END_SMM_INIT_START,(UINT64)DriverEntry->SmmLoadedImage.ImageBase, (UINT64)DriverEntry->SmmLoadedImage.ImageBase + (UINT64)DriverEntry->SmmLoadedImage.ImageSize);
          DEBUG((DEBUG_INFO,"vendor smm core start\n"));
          SmmFuzzGlobalData->in_fuzz = 1;
          Status = ((EFI_IMAGE_ENTRY_POINT)(UINTN)DriverEntry->ImageEntryPoint)(ImageHandle, gST);
          SmmFuzzGlobalData->in_fuzz = 0;
          DEBUG((DEBUG_INFO,"vendor smm core end %r\n",Status));
          if (EFI_ERROR (Status)) {
            LIBAFL_QEMU_END(LIBAFL_QEMU_END_SMM_INIT_UNSUPPORT,0,0);  
          } else {
            LIBAFL_QEMU_END(LIBAFL_QEMU_END_SMM_INIT_END,0,0);  
          }
          
          gSmmCorePrivate->SmramRanges = OldSmramRange;
          ASSERT_EFI_ERROR (Status);
          return Status;
      }
    }
  }
  return EFI_NOT_FOUND;

}
volatile UINT64 SmmFuzzDummyMemory = 10;
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
  //
  // Get SMM Core Private context passed in from SMM IPL in ImageHandle.
  //
  gSmmCorePrivate = (SMM_CORE_PRIVATE_DATA *)ImageHandle;
  Status = LoadVendorCore(ImageHandle, SystemTable);
  if (!EFI_ERROR(Status))
  {
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

EFI_STATUS InstallSmmFuzzSmiHandler(VOID)
{
  EFI_HANDLE Handle = NULL;
  EFI_STATUS Status = SmiHandlerRegister(
               SmmReportHandler,
               &gEfiSmmReportSmmModuleInfoGuid,
               &Handle
               );
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
  SMM_MODULES_HANDLER_PROTOCOL_INFO *data = (SMM_MODULES_HANDLER_PROTOCOL_INFO*)CommBuffer;
  LIST_ENTRY  *Link;
  EFI_SMM_DRIVER_ENTRY  *DriverEntry;
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
  SmmModulesHandlerProtocolInfo.Test = &Test;
  CopyMem(data,&SmmModulesHandlerProtocolInfo, sizeof(SmmModulesHandlerProtocolInfo));

  for (Link = mDiscoveredList.ForwardLink; Link != &mDiscoveredList; Link = Link->ForwardLink) {
    DriverEntry = CR (Link, EFI_SMM_DRIVER_ENTRY, Link, EFI_SMM_DRIVER_ENTRY_SIGNATURE);
    if (DriverEntry->Dependent && data->NumNonLoadedModules < MAX_NUM_NONLOADED_MODULES) {
      CopyGuid(&data->NonLoadedModules[data->NumNonLoadedModules++], &DriverEntry->FileName);
    }
  }
  return EFI_SUCCESS;
}
VOID InsertNewSmmModule(GUID *Guid, VOID *Addr, UINT64 Size)
{
  if (SmmModulesHandlerProtocolInfo.NumModules >= MAX_NUM_MODULES)
    return;
  CopyGuid(&SmmModulesHandlerProtocolInfo.info[SmmModulesHandlerProtocolInfo.NumModules].Guid, Guid);
  SmmModulesHandlerProtocolInfo.info[SmmModulesHandlerProtocolInfo.NumModules].ImageBase = Addr;
  SmmModulesHandlerProtocolInfo.info[SmmModulesHandlerProtocolInfo.NumModules].ImageSize = Size;
  SmmModulesHandlerProtocolInfo.NumModules++;
}
VOID InsertSmiHandler(CONST GUID *Handler)
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
    if (SmmModulesHandlerProtocolInfo.info[i].NumSmiHandlers >= MAX_NUM_HANDLERS)
      return;
    CopyGuid(&SmmModulesHandlerProtocolInfo.info[i].SmiHandlers[SmmModulesHandlerProtocolInfo.info[i].NumSmiHandlers++], Handler);
    return;
  }
  if (SmmModulesHandlerProtocolInfo.NumUnclassifiedSmiHandlers >= MAX_NUM_UNCLASSIFIED_HANDLERS)
    return;
  CopyGuid(&SmmModulesHandlerProtocolInfo.UnclassifiedSmiHandlers[SmmModulesHandlerProtocolInfo.NumUnclassifiedSmiHandlers++], Handler);
}
VOID InsertRootSmiHandler(VOID)
{
  SmmModulesHandlerProtocolInfo.NumRootSmiHandlers++;
}
VOID InsertProduceProtocol(CONST GUID *Protocol)
{
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
  for (UINTN i = 0; i < SmmModulesHandlerProtocolInfo.NumUnclassifiedProtocols; i++)
  {
    if (CompareGuid(&SmmModulesHandlerProtocolInfo.UnclassifiedProtocols[i],Protocol))
    {
      return;
    }
  }
  if (SmmModulesHandlerProtocolInfo.NumUnclassifiedProtocols >= MAX_NUM_UNCLASSIFIED_PROTOCOLS) 
  {
    return;
  }
  CopyGuid(&SmmModulesHandlerProtocolInfo.UnclassifiedProtocols[SmmModulesHandlerProtocolInfo.NumUnclassifiedProtocols++], Protocol);
}
VOID InsertConsumeProtocol(CONST GUID *Protocol)
{
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
      if (CompareGuid(&SmmModulesHandlerProtocolInfo.info[i].SmiHandlers[j], guid))
      {
        SetCurrentModule(&SmmModulesHandlerProtocolInfo.info[i].Guid);
        return;
      }
    }
  }
  ClearCurrentModule();
}