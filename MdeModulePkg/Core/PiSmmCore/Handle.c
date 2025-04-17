/** @file
  SMM handle & protocol handling.

  Copyright (c) 2009 - 2018, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "PiSmmCore.h"

EFI_INSTALL_PROTOCOL_INTERFACE      SmmInstallProtocolInterfaceOld = NULL;
EFI_UNINSTALL_PROTOCOL_INTERFACE    SmmUninstallProtocolInterfaceOld = NULL;
EFI_HANDLE_PROTOCOL                 SmmHandleProtocolOld = NULL;
EFI_SMM_REGISTER_PROTOCOL_NOTIFY    SmmRegisterProtocolNotifyOld = NULL;
EFI_LOCATE_HANDLE                   SmmLocateHandleOld = NULL;
EFI_LOCATE_PROTOCOL                 SmmLocateProtocolOld = NULL;
EFI_SMM_INTERRUPT_MANAGE            SmiManageOld = NULL;
EFI_SMM_INTERRUPT_REGISTER          SmiHandlerRegisterOld = NULL;
EFI_SMM_INTERRUPT_UNREGISTER        SmiHandlerUnRegisterOld = NULL;
EFI_ALLOCATE_POOL                   SmmAllocatePoolOld = NULL;
EFI_FREE_POOL                       SmmFreePoolOld = NULL;
EFI_ALLOCATE_PAGES                  SmmAllocatePagesOld = NULL;
EFI_FREE_PAGES                      SmmFreePagesOld = NULL;
EFI_SMM_STARTUP_THIS_AP             SmmStartupThisAp = NULL;
//
// mProtocolDatabase     - A list of all protocols in the system.  (simple list for now)
// gHandleList           - A list of all the handles in the system
//
LIST_ENTRY  mProtocolDatabase = INITIALIZE_LIST_HEAD_VARIABLE (mProtocolDatabase);
LIST_ENTRY  gHandleList       = INITIALIZE_LIST_HEAD_VARIABLE (gHandleList);

/**
  Check whether a handle is a valid EFI_HANDLE

  @param  UserHandle             The handle to check

  @retval EFI_INVALID_PARAMETER  The handle is NULL or not a valid EFI_HANDLE.
  @retval EFI_SUCCESS            The handle is valid EFI_HANDLE.

**/
EFI_STATUS
SmmValidateHandle (
  IN EFI_HANDLE  UserHandle
  )
{
  IHANDLE  *Handle;

  Handle = (IHANDLE *)UserHandle;
  if (Handle == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (Handle->Signature != EFI_HANDLE_SIGNATURE) {
    return EFI_INVALID_PARAMETER;
  }

  return EFI_SUCCESS;
}

/**
  Finds the protocol entry for the requested protocol.

  @param  Protocol               The ID of the protocol
  @param  Create                 Create a new entry if not found

  @return Protocol entry

**/
PROTOCOL_ENTRY  *
SmmFindProtocolEntry (
  IN EFI_GUID  *Protocol,
  IN BOOLEAN   Create
  )
{
  LIST_ENTRY      *Link;
  PROTOCOL_ENTRY  *Item;
  PROTOCOL_ENTRY  *ProtEntry;

  //
  // Search the database for the matching GUID
  //

  ProtEntry = NULL;
  for (Link = mProtocolDatabase.ForwardLink;
       Link != &mProtocolDatabase;
       Link = Link->ForwardLink)
  {
    Item = CR (Link, PROTOCOL_ENTRY, AllEntries, PROTOCOL_ENTRY_SIGNATURE);
    if (CompareGuid (&Item->ProtocolID, Protocol)) {
      //
      // This is the protocol entry
      //
      ProtEntry = Item;
      break;
    }
  }

  //
  // If the protocol entry was not found and Create is TRUE, then
  // allocate a new entry
  //
  if ((ProtEntry == NULL) && Create) {
    ProtEntry = AllocatePool (sizeof (PROTOCOL_ENTRY));
    if (ProtEntry != NULL) {
      //
      // Initialize new protocol entry structure
      //
      ProtEntry->Signature = PROTOCOL_ENTRY_SIGNATURE;
      CopyGuid ((VOID *)&ProtEntry->ProtocolID, Protocol);
      InitializeListHead (&ProtEntry->Protocols);
      InitializeListHead (&ProtEntry->Notify);

      //
      // Add it to protocol database
      //
      InsertTailList (&mProtocolDatabase, &ProtEntry->AllEntries);
    }
  }

  return ProtEntry;
}

/**
  Finds the protocol instance for the requested handle and protocol.
  Note: This function doesn't do parameters checking, it's caller's responsibility
  to pass in valid parameters.

  @param  Handle                 The handle to search the protocol on
  @param  Protocol               GUID of the protocol
  @param  Interface              The interface for the protocol being searched

  @return Protocol instance (NULL: Not found)

**/
PROTOCOL_INTERFACE *
SmmFindProtocolInterface (
  IN IHANDLE   *Handle,
  IN EFI_GUID  *Protocol,
  IN VOID      *Interface
  )
{
  PROTOCOL_INTERFACE  *Prot;
  PROTOCOL_ENTRY      *ProtEntry;
  LIST_ENTRY          *Link;

  Prot = NULL;

  //
  // Lookup the protocol entry for this protocol ID
  //
  ProtEntry = SmmFindProtocolEntry (Protocol, FALSE);
  if (ProtEntry != NULL) {
    //
    // Look at each protocol interface for any matches
    //
    for (Link = Handle->Protocols.ForwardLink; Link != &Handle->Protocols; Link = Link->ForwardLink) {
      //
      // If this protocol interface matches, remove it
      //
      Prot = CR (Link, PROTOCOL_INTERFACE, Link, PROTOCOL_INTERFACE_SIGNATURE);
      if ((Prot->Interface == Interface) && (Prot->Protocol == ProtEntry)) {
        break;
      }

      Prot = NULL;
    }
  }

  return Prot;
}
UINTN TmpInterface;
/**
  Wrapper function to SmmInstallProtocolInterfaceNotify.  This is the public API which
  Calls the private one which contains a BOOLEAN parameter for notifications

  @param  UserHandle             The handle to install the protocol handler on,
                                 or NULL if a new handle is to be allocated
  @param  Protocol               The protocol to add to the handle
  @param  InterfaceType          Indicates whether Interface is supplied in
                                 native form.
  @param  Interface              The interface for the protocol being added

  @return Status code

**/
EFI_STATUS
EFIAPI
SmmInstallProtocolInterface (
  IN OUT EFI_HANDLE      *UserHandle,
  IN EFI_GUID            *Protocol,
  IN EFI_INTERFACE_TYPE  InterfaceType,
  IN VOID                *Interface
  )
{
  DEBUG((DEBUG_INFO,"SmmInstallProtocolInterface: %g %p\n",Protocol,Interface));
  InsertProduceProtocol(Protocol);
  return SmmInstallProtocolInterfaceNotify (
           UserHandle,
           Protocol,
           InterfaceType,
           Interface,
           TRUE
           );
}

typedef struct _AMI_DIGITAL_SIGNATURE_PROTOCOL AMI_DIGITAL_SIGNATURE_PROTOCOL;
typedef struct{
  EFI_GUID AlgGuid;
  UINT32 BlobSize;
  UINT8 *Blob;
} CRYPT_HANDLE;
typedef 
EFI_STATUS
(EFIAPI *AMI_DIGITAL_SIGNATURE_PKCS1_VERIFY) (
  IN CONST AMI_DIGITAL_SIGNATURE_PROTOCOL *This,
  IN CRYPT_HANDLE *PublicKey,
  IN CRYPT_HANDLE *Hash,
  IN VOID *Signature,
  IN UINTN SignatureSize,
  IN UINT32 Flags
);

typedef 
EFI_STATUS
(EFIAPI *AMI_DIGITAL_SIGNATURE_PKCS7_VERIFY) (
  IN CONST AMI_DIGITAL_SIGNATURE_PROTOCOL *This,
  IN CONST UINT8 *P7Data,
  IN UINTN        P7Size,
  IN CONST UINT8 *TrustedCert,
  IN UINTN        CertSize,
  IN OUT UINT8  **Data,
  IN OUT UINTN   *DataSize,
  IN UINT8        Operation,
  IN UINT32       Flags
);

typedef 
EFI_STATUS
(EFIAPI *AMI_DIGITAL_SIGNATURE_HASH) (
  IN CONST AMI_DIGITAL_SIGNATURE_PROTOCOL *This,
  IN CONST EFI_GUID *HashAlgorithm,
  IN UINTN Num_elem,
  IN CONST UINT8 *Addr[],
  IN CONST UINTN *Len,
  OUT UINT8 *Hash
);

typedef
EFI_STATUS
(EFIAPI *AMI_DIGITAL_SIGNATURE_GET_KEY) (
  IN CONST AMI_DIGITAL_SIGNATURE_PROTOCOL *This,
  OUT CRYPT_HANDLE *Key,
  IN EFI_GUID *AlgId,
  IN UINTN KeyLen,
  IN UINT32 Flags
  );

typedef
EFI_STATUS
(EFIAPI *AMI_DIGITAL_SIGNATURE_VERIFY_KEY) (
  IN CONST AMI_DIGITAL_SIGNATURE_PROTOCOL *This,
  IN EFI_GUID       *AlgId,
  IN CRYPT_HANDLE   *Key
  );
struct _AMI_DIGITAL_SIGNATURE_PROTOCOL  {
  AMI_DIGITAL_SIGNATURE_PKCS1_VERIFY Pkcs1Verify;
  AMI_DIGITAL_SIGNATURE_PKCS7_VERIFY Pkcs7Verify;
  AMI_DIGITAL_SIGNATURE_HASH Hash;
  AMI_DIGITAL_SIGNATURE_GET_KEY GetKey;
  AMI_DIGITAL_SIGNATURE_VERIFY_KEY VerifyKey;
};

EFI_STATUS
EFIAPI AMI_DIGITAL_SIGNATURE_GET_KEY_FUZZ (
  IN CONST AMI_DIGITAL_SIGNATURE_PROTOCOL *This,
  OUT CRYPT_HANDLE *Key,
  IN EFI_GUID *AlgId,
  IN UINTN KeyLen,
  IN UINT32 Flags
) {
  Key->BlobSize = 0x20;
  Key->AlgGuid = *AlgId;
  if(Key->Blob) 
    Key->Blob = (UINT8 *)0x2000000000000000;
  DEBUG((DEBUG_INFO,"AMI_DIGITAL_SIGNATURE_GET_KEY_FUZZ: %g %p %p\n",AlgId, Key, &Key->Blob));
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
SmmInstallProtocolInterfaceFuzz (
  IN OUT EFI_HANDLE      *UserHandle,
  IN EFI_GUID            *Protocol,
  IN EFI_INTERFACE_TYPE  InterfaceType,
  IN VOID                *Interface
  )
{
  VOID *TmpInterface;
  if (SmmLocateProtocol(Protocol, NULL, &TmpInterface) == EFI_SUCCESS)
    return EFI_SUCCESS;
  static EFI_GUID gAmiSmmDigitalSignatureProtocolGuid = { 0x91ABC830, 0x16FC, 0x4D9E, {0xA1, 0x89, 0x5F, 0xC8, 0xBB, 0x41, 0x14, 0x02 }};
  if (CompareGuid(Protocol, &gAmiSmmDigitalSignatureProtocolGuid)) {
    AMI_DIGITAL_SIGNATURE_PROTOCOL *AmiSmmDigitalSignatureProtocol = (AMI_DIGITAL_SIGNATURE_PROTOCOL *)Interface;
    AmiSmmDigitalSignatureProtocol->GetKey = AMI_DIGITAL_SIGNATURE_GET_KEY_FUZZ;
  }
  
  EFI_STATUS Status = SmmInstallProtocolInterface(UserHandle, Protocol, InterfaceType, Interface);
  return Status;
}
/**
  Installs a protocol interface into the boot services environment.

  @param  UserHandle             The handle to install the protocol handler on,
                                 or NULL if a new handle is to be allocated
  @param  Protocol               The protocol to add to the handle
  @param  InterfaceType          Indicates whether Interface is supplied in
                                 native form.
  @param  Interface              The interface for the protocol being added
  @param  Notify                 indicates whether notify the notification list
                                 for this protocol

  @retval EFI_INVALID_PARAMETER  Invalid parameter
  @retval EFI_OUT_OF_RESOURCES   No enough buffer to allocate
  @retval EFI_SUCCESS            Protocol interface successfully installed

**/
EFI_STATUS
SmmInstallProtocolInterfaceNotify (
  IN OUT EFI_HANDLE          *UserHandle,
  IN     EFI_GUID            *Protocol,
  IN     EFI_INTERFACE_TYPE  InterfaceType,
  IN     VOID                *Interface,
  IN     BOOLEAN             Notify
  )
{
  PROTOCOL_INTERFACE  *Prot;
  PROTOCOL_ENTRY      *ProtEntry;
  IHANDLE             *Handle;
  EFI_STATUS          Status;
  VOID                *ExistingInterface;

  //
  // returns EFI_INVALID_PARAMETER if InterfaceType is invalid.
  // Also added check for invalid UserHandle and Protocol pointers.
  //
  if ((UserHandle == NULL) || (Protocol == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  if (InterfaceType != EFI_NATIVE_INTERFACE) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Print debug message
  //
  DEBUG ((DEBUG_LOAD | DEBUG_INFO, "SmmInstallProtocolInterface2: %g %p\n", Protocol, Interface));

  Status = EFI_OUT_OF_RESOURCES;
  Prot   = NULL;
  Handle = NULL;

  if (*UserHandle != NULL) {
    Status = SmmHandleProtocol (*UserHandle, Protocol, (VOID **)&ExistingInterface);
    if (!EFI_ERROR (Status)) {
      return EFI_INVALID_PARAMETER;
    }
  }

  //
  // Lookup the Protocol Entry for the requested protocol
  //
  ProtEntry = SmmFindProtocolEntry (Protocol, TRUE);
  if (ProtEntry == NULL) {
    goto Done;
  }

  //
  // Allocate a new protocol interface structure
  //
  Prot = AllocateZeroPool (sizeof (PROTOCOL_INTERFACE));
  if (Prot == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto Done;
  }

  //
  // If caller didn't supply a handle, allocate a new one
  //
  Handle = (IHANDLE *)*UserHandle;
  if (Handle == NULL) {
    Handle = AllocateZeroPool (sizeof (IHANDLE));
    if (Handle == NULL) {
      Status = EFI_OUT_OF_RESOURCES;
      goto Done;
    }

    //
    // Initialize new handler structure
    //
    Handle->Signature = EFI_HANDLE_SIGNATURE;
    InitializeListHead (&Handle->Protocols);

    //
    // Add this handle to the list global list of all handles
    // in the system
    //
    InsertTailList (&gHandleList, &Handle->AllHandles);
  } else {
    Status = SmmValidateHandle (Handle);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "SmmInstallProtocolInterface: input handle at 0x%x is invalid\n", Handle));
      goto Done;
    }
  }

  //
  // Each interface that is added must be unique
  //
  ASSERT (SmmFindProtocolInterface (Handle, Protocol, Interface) == NULL);

  //
  // Initialize the protocol interface structure
  //
  Prot->Signature = PROTOCOL_INTERFACE_SIGNATURE;
  Prot->Handle    = Handle;
  Prot->Protocol  = ProtEntry;
  Prot->Interface = Interface;

  //
  // Add this protocol interface to the head of the supported
  // protocol list for this handle
  //
  InsertHeadList (&Handle->Protocols, &Prot->Link);

  //
  // Add this protocol interface to the tail of the
  // protocol entry
  //
  InsertTailList (&ProtEntry->Protocols, &Prot->ByProtocol);

  //
  // Notify the notification list for this protocol
  //
  if (Notify) {
    DEBUG((DEBUG_INFO,"Protocol notify %g\n",Protocol));
    SmmNotifyProtocol (Prot);
  }

  Status = EFI_SUCCESS;

Done:
  if (!EFI_ERROR (Status)) {
    //
    // Return the new handle back to the caller
    //
    *UserHandle = Handle;
  } else {
    //
    // There was an error, clean up
    //
    if (Prot != NULL) {
      FreePool (Prot);
    }

    DEBUG ((DEBUG_ERROR, "SmmInstallProtocolInterface: %g %p failed with %r\n", Protocol, Interface, Status));
  }

  return Status;
}

/**
  Uninstalls all instances of a protocol:interfacer from a handle.
  If the last protocol interface is remove from the handle, the
  handle is freed.

  @param  UserHandle             The handle to remove the protocol handler from
  @param  Protocol               The protocol, of protocol:interface, to remove
  @param  Interface              The interface, of protocol:interface, to remove

  @retval EFI_INVALID_PARAMETER  Protocol is NULL.
  @retval EFI_SUCCESS            Protocol interface successfully uninstalled.

**/
EFI_STATUS
EFIAPI
SmmUninstallProtocolInterface (
  IN EFI_HANDLE  UserHandle,
  IN EFI_GUID    *Protocol,
  IN VOID        *Interface
  )
{
  DEBUG((DEBUG_INFO,"SmmUninstallProtocolInterface: %g\n",Protocol));
  EFI_STATUS          Status;
  IHANDLE             *Handle;
  PROTOCOL_INTERFACE  *Prot;

  //
  // Check that Protocol is valid
  //
  if (Protocol == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Check that UserHandle is a valid handle
  //
  Status = SmmValidateHandle (UserHandle);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Check that Protocol exists on UserHandle, and Interface matches the interface in the database
  //
  Prot = SmmFindProtocolInterface (UserHandle, Protocol, Interface);
  if (Prot == NULL) {
    return EFI_NOT_FOUND;
  }

  //
  // Remove the protocol interface from the protocol
  //
  Status = EFI_NOT_FOUND;
  Handle = (IHANDLE *)UserHandle;
  Prot   = SmmRemoveInterfaceFromProtocol (Handle, Protocol, Interface);

  if (Prot != NULL) {
    //
    // Remove the protocol interface from the handle
    //
    RemoveEntryList (&Prot->Link);

    //
    // Free the memory
    //
    Prot->Signature = 0;
    FreePool (Prot);
    Status = EFI_SUCCESS;
  }

  //
  // If there are no more handlers for the handle, free the handle
  //
  if (IsListEmpty (&Handle->Protocols)) {
    Handle->Signature = 0;
    RemoveEntryList (&Handle->AllHandles);
    FreePool (Handle);
  }

  return Status;
}


EFI_STATUS
EFIAPI
SmmUninstallProtocolInterfaceFuzz (
  IN EFI_HANDLE  UserHandle,
  IN EFI_GUID    *Protocol,
  IN VOID        *Interface
  )
{
  EFI_STATUS Status = SmmUninstallProtocolInterface(UserHandle, Protocol, Interface);
  return Status;
}
/**
  Locate a certain GUID protocol interface in a Handle's protocols.

  @param  UserHandle             The handle to obtain the protocol interface on
  @param  Protocol               The GUID of the protocol

  @return The requested protocol interface for the handle

**/
PROTOCOL_INTERFACE  *
SmmGetProtocolInterface (
  IN EFI_HANDLE  UserHandle,
  IN EFI_GUID    *Protocol
  )
{
  EFI_STATUS          Status;
  PROTOCOL_ENTRY      *ProtEntry;
  PROTOCOL_INTERFACE  *Prot;
  IHANDLE             *Handle;
  LIST_ENTRY          *Link;

  Status = SmmValidateHandle (UserHandle);
  if (EFI_ERROR (Status)) {
    return NULL;
  }

  Handle = (IHANDLE *)UserHandle;

  //
  // Look at each protocol interface for a match
  //
  for (Link = Handle->Protocols.ForwardLink; Link != &Handle->Protocols; Link = Link->ForwardLink) {
    Prot      = CR (Link, PROTOCOL_INTERFACE, Link, PROTOCOL_INTERFACE_SIGNATURE);
    ProtEntry = Prot->Protocol;
    if (CompareGuid (&ProtEntry->ProtocolID, Protocol)) {
      return Prot;
    }
  }

  return NULL;
}

/**
  Queries a handle to determine if it supports a specified protocol.

  @param  UserHandle             The handle being queried.
  @param  Protocol               The published unique identifier of the protocol.
  @param  Interface              Supplies the address where a pointer to the
                                 corresponding Protocol Interface is returned.

  @retval EFI_SUCCESS            The interface information for the specified protocol was returned.
  @retval EFI_UNSUPPORTED        The device does not support the specified protocol.
  @retval EFI_INVALID_PARAMETER  Handle is not a valid EFI_HANDLE..
  @retval EFI_INVALID_PARAMETER  Protocol is NULL.
  @retval EFI_INVALID_PARAMETER  Interface is NULL.

**/
EFI_STATUS
EFIAPI
SmmHandleProtocol (
  IN  EFI_HANDLE  UserHandle,
  IN  EFI_GUID    *Protocol,
  OUT VOID        **Interface
  )
{
  InsertConsumeProtocol(Protocol);
  EFI_STATUS          Status;
  PROTOCOL_INTERFACE  *Prot;

  //
  // Check for invalid Protocol
  //
  if (Protocol == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Check for invalid Interface
  //
  if (Interface == NULL) {
    return EFI_INVALID_PARAMETER;
  } else {
    *Interface = NULL;
  }

  //
  // Check for invalid UserHandle
  //
  Status = SmmValidateHandle (UserHandle);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Look at each protocol interface for a match
  //
  Prot = SmmGetProtocolInterface (UserHandle, Protocol);
  if (Prot == NULL) {
    if (SmmHandleProtocolOld)
      return SmmHandleProtocolOld(UserHandle, Protocol, Interface);
    return EFI_UNSUPPORTED;
  }

  //
  // This is the protocol interface entry for this protocol
  //
  *Interface = Prot->Interface;

  return EFI_SUCCESS;
}
EFI_STATUS
EFIAPI
SmmHandleProtocolFuzz (
  IN  EFI_HANDLE  UserHandle,
  IN  EFI_GUID    *Protocol,
  OUT VOID        **Interface
  )
{
  EFI_STATUS Status;
  Status = SmmHandleProtocol(UserHandle, Protocol, Interface);
  DEBUG((DEBUG_INFO,"SmmHandleProtocol: %g %r\n",Protocol, Status));
  return Status;
}