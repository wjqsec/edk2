/** @file
  Support functions for UEFI protocol notification infrastructure.

  Copyright (c) 2009 - 2018, Intel Corporation. All rights reserved.<BR>
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

/**
  Signal event for every protocol in protocol entry.

  @param  Prot                   Protocol interface

**/
VOID
SmmNotifyProtocol (
  IN PROTOCOL_INTERFACE  *Prot
  )
{
  PROTOCOL_ENTRY   *ProtEntry;
  PROTOCOL_NOTIFY  *ProtNotify;
  LIST_ENTRY       *Link;

  BOOLEAN ToFuzz = CompareGuid(&Prot->Protocol->ProtocolID, &gEfiSmmEndOfDxeProtocolGuid) || CompareGuid(&Prot->Protocol->ProtocolID, &gEfiSmmReadyToLockProtocolGuid);
  ProtEntry = Prot->Protocol;
  for (Link = ProtEntry->Notify.ForwardLink; Link != &ProtEntry->Notify; Link = Link->ForwardLink) {
    
    ProtNotify = CR (Link, PROTOCOL_NOTIFY, Link, PROTOCOL_NOTIFY_SIGNATURE);
    GUID Module;
    GUID OldModule = GetCurrentModule();
    if (GetModuleFromAddr((UINT64)ProtNotify->Function, &Module))
    {
      if (!IsOVMFSmmModule(&Module)) {
        SetCurrentModule(&Module);
      }
    }
    if (ToFuzz)
    {
      DEBUG((DEBUG_INFO,"EndofDXE Notify %p\n",ProtNotify->Function));
      LIBAFL_QEMU_END(LIBAFL_QEMU_END_SMM_INIT_PREPARE,0,0);
      LIBAFL_QEMU_SMM_REPORT_LOCKBOX((libafl_word)ProtNotify->Function);
      LIBAFL_QEMU_END(LIBAFL_QEMU_END_SMM_INIT_START,0,0);
      UINTN skip = LIBAFL_QEMU_SMM_ASK_SKIP_MODULE();
      if (skip == 0) {
        ProtNotify->Function (&ProtEntry->ProtocolID, Prot->Interface, Prot->Handle);
      }
      LIBAFL_QEMU_END(LIBAFL_QEMU_END_SMM_INIT_END,0,0);  
    }
    else
      ProtNotify->Function (&ProtEntry->ProtocolID, Prot->Interface, Prot->Handle);
    SetCurrentModule(&OldModule);
  }
}

/**
  Removes Protocol from the protocol list (but not the handle list).

  @param  Handle                 The handle to remove protocol on.
  @param  Protocol               GUID of the protocol to be moved
  @param  Interface              The interface of the protocol

  @return Protocol Entry

**/
PROTOCOL_INTERFACE *
SmmRemoveInterfaceFromProtocol (
  IN IHANDLE   *Handle,
  IN EFI_GUID  *Protocol,
  IN VOID      *Interface
  )
{
  PROTOCOL_INTERFACE  *Prot;
  PROTOCOL_NOTIFY     *ProtNotify;
  PROTOCOL_ENTRY      *ProtEntry;
  LIST_ENTRY          *Link;

  Prot = SmmFindProtocolInterface (Handle, Protocol, Interface);
  if (Prot != NULL) {
    ProtEntry = Prot->Protocol;

    //
    // If there's a protocol notify location pointing to this entry, back it up one
    //
    for (Link = ProtEntry->Notify.ForwardLink; Link != &ProtEntry->Notify; Link = Link->ForwardLink) {
      ProtNotify = CR (Link, PROTOCOL_NOTIFY, Link, PROTOCOL_NOTIFY_SIGNATURE);

      if (ProtNotify->Position == &Prot->ByProtocol) {
        ProtNotify->Position = Prot->ByProtocol.BackLink;
      }
    }

    //
    // Remove the protocol interface entry
    //
    RemoveEntryList (&Prot->ByProtocol);
  }

  return Prot;
}

/**
  Add a new protocol notification record for the request protocol.

  @param  Protocol               The requested protocol to add the notify
                                 registration
  @param  Function               Points to the notification function
  @param  Registration           Returns the registration record

  @retval EFI_SUCCESS            Successfully returned the registration record
                                 that has been added or unhooked
  @retval EFI_INVALID_PARAMETER  Protocol is NULL or Registration is NULL
  @retval EFI_OUT_OF_RESOURCES   Not enough memory resource to finish the request
  @retval EFI_NOT_FOUND          If the registration is not found when Function == NULL

**/
EFI_STATUS
EFIAPI
SmmRegisterProtocolNotify (
  IN  CONST EFI_GUID     *Protocol,
  IN  EFI_SMM_NOTIFY_FN  Function,
  OUT VOID               **Registration
  )
{
  DEBUG((DEBUG_INFO,"SmmRegisterProtocolNotify: %g\n",Protocol));
  PROTOCOL_ENTRY   *ProtEntry;
  PROTOCOL_NOTIFY  *ProtNotify;
  LIST_ENTRY       *Link;
  EFI_STATUS       Status;

  if ((Protocol == NULL) || (Registration == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  if (Function == NULL) {
    //
    // Get the protocol entry per Protocol
    //
    ProtEntry = SmmFindProtocolEntry ((EFI_GUID *)Protocol, FALSE);
    if (ProtEntry != NULL) {
      ProtNotify = (PROTOCOL_NOTIFY *)*Registration;
      for (Link = ProtEntry->Notify.ForwardLink;
           Link != &ProtEntry->Notify;
           Link = Link->ForwardLink)
      {
        //
        // Compare the notification record
        //
        if (ProtNotify == (CR (Link, PROTOCOL_NOTIFY, Link, PROTOCOL_NOTIFY_SIGNATURE))) {
          //
          // If Registration is an existing registration, then unhook it
          //
          ProtNotify->Signature = 0;
          RemoveEntryList (&ProtNotify->Link);
          FreePool (ProtNotify);
          return EFI_SUCCESS;
        }
      }
    }

    //
    // If the registration is not found
    //
    return EFI_NOT_FOUND;
  }

  ProtNotify = NULL;

  //
  // Get the protocol entry to add the notification too
  //
  ProtEntry = SmmFindProtocolEntry ((EFI_GUID *)Protocol, TRUE);
  if (ProtEntry != NULL) {
    //
    // Find whether notification already exist
    //
    for (Link = ProtEntry->Notify.ForwardLink;
         Link != &ProtEntry->Notify;
         Link = Link->ForwardLink)
    {
      ProtNotify = CR (Link, PROTOCOL_NOTIFY, Link, PROTOCOL_NOTIFY_SIGNATURE);
      if (CompareGuid (&ProtNotify->Protocol->ProtocolID, Protocol) &&
          (ProtNotify->Function == Function))
      {
        //
        // Notification already exist
        //
        *Registration = ProtNotify;

        return EFI_SUCCESS;
      }
    }

    //
    // Allocate a new notification record
    //
    ProtNotify = AllocatePool (sizeof (PROTOCOL_NOTIFY));
    if (ProtNotify != NULL) {
      ProtNotify->Signature = PROTOCOL_NOTIFY_SIGNATURE;
      ProtNotify->Protocol  = ProtEntry;
      ProtNotify->Function  = Function;
      //
      // Start at the ending
      //
      ProtNotify->Position = ProtEntry->Protocols.BackLink;
      InsertTailList (&ProtEntry->Notify, &ProtNotify->Link);
      DEBUG((DEBUG_INFO,"Add Notification %g %p\n",Protocol,ProtNotify->Protocol));
    }
  }

  //
  // Done.  If we have a protocol notify entry, then return it.
  // Otherwise, we must have run out of resources trying to add one
  //
  Status = EFI_OUT_OF_RESOURCES;
  if (ProtNotify != NULL) {
    *Registration = ProtNotify;
    Status        = EFI_SUCCESS;
  }

  return Status;
}
EFI_STATUS
EFIAPI
SmmRegisterProtocolNotifyFuzz (
  IN  CONST EFI_GUID     *Protocol,
  IN  EFI_SMM_NOTIFY_FN  Function,
  OUT VOID               **Registration
  )
{
  EFI_STATUS Status = SmmRegisterProtocolNotify(Protocol, Function, Registration);
  return Status;
}