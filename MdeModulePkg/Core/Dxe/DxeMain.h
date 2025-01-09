/** @file
  The internal header file includes the common header files, defines
  internal structure and functions used by DxeCore module.

Copyright (c) 2006 - 2018, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _DXE_MAIN_H_
#define _DXE_MAIN_H_

#include <PiDxe.h>

#include <Protocol/LoadedImage.h>
#include <Protocol/GuidedSectionExtraction.h>
#include <Protocol/DevicePath.h>
#include <Protocol/Runtime.h>
#include <Protocol/LoadFile.h>
#include <Protocol/LoadFile2.h>
#include <Protocol/DriverBinding.h>
#include <Protocol/VariableWrite.h>
#include <Protocol/PlatformDriverOverride.h>
#include <Protocol/Variable.h>
#include <Protocol/Timer.h>
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/Bds.h>
#include <Protocol/RealTimeClock.h>
#include <Protocol/WatchdogTimer.h>
#include <Protocol/FirmwareVolume2.h>
#include <Protocol/MonotonicCounter.h>
#include <Protocol/StatusCode.h>
#include <Protocol/Decompress.h>
#include <Protocol/LoadPe32Image.h>
#include <Protocol/Security.h>
#include <Protocol/Security2.h>
#include <Protocol/Reset.h>
#include <Protocol/Cpu.h>
#include <Protocol/Metronome.h>
#include <Protocol/FirmwareVolumeBlock.h>
#include <Protocol/Capsule.h>
#include <Protocol/BusSpecificDriverOverride.h>
#include <Protocol/DriverFamilyOverride.h>
#include <Protocol/TcgService.h>
#include <Protocol/HiiPackageList.h>
#include <Protocol/SmmBase2.h>
#include <Protocol/PeCoffImageEmulator.h>
#include <Guid/MemoryTypeInformation.h>
#include <Guid/FirmwareFileSystem2.h>
#include <Guid/FirmwareFileSystem3.h>
#include <Guid/HobList.h>
#include <Guid/DebugImageInfoTable.h>
#include <Guid/FileInfo.h>
#include <Guid/Apriori.h>
#include <Guid/DxeServices.h>
#include <Guid/MemoryAllocationHob.h>
#include <Guid/EventLegacyBios.h>
#include <Guid/EventGroup.h>
#include <Guid/EventExitBootServiceFailed.h>
#include <Guid/LoadModuleAtFixedAddress.h>
#include <Guid/IdleLoopEvent.h>
#include <Guid/VectorHandoffTable.h>
#include <Ppi/VectorHandoffInfo.h>
#include <Guid/MemoryProfile.h>

#include <Library/DxeCoreEntryPoint.h>
#include <Library/DebugLib.h>
#include <Library/UefiLib.h>
#include <Library/BaseLib.h>
#include <Library/HobLib.h>
#include <Library/PerformanceLib.h>
#include <Library/UefiDecompressLib.h>
#include <Library/ExtractGuidedSectionLib.h>
#include <Library/CacheMaintenanceLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/PeCoffLib.h>
#include <Library/PeCoffGetEntryPointLib.h>
#include <Library/PeCoffExtraActionLib.h>
#include <Library/PcdLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DevicePathLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/ReportStatusCodeLib.h>
#include <Library/DxeServicesLib.h>
#include <Library/DebugAgentLib.h>
#include <Library/CpuExceptionHandlerLib.h>
#include <Library/OrderedCollectionLib.h>

//
// attributes for reserved memory before it is promoted to system memory
//
#define EFI_MEMORY_PRESENT      0x0100000000000000ULL
#define EFI_MEMORY_INITIALIZED  0x0200000000000000ULL
#define EFI_MEMORY_TESTED       0x0400000000000000ULL

//
// range for memory mapped port I/O on IPF
//
#define EFI_MEMORY_PORT_IO  0x4000000000000000ULL

///
/// EFI_DEP_REPLACE_TRUE - Used to dynamically patch the dependency expression
///                        to save time.  A EFI_DEP_PUSH is evaluated one an
///                        replaced with EFI_DEP_REPLACE_TRUE. If PI spec's Vol 2
///                        Driver Execution Environment Core Interface use 0xff
///                        as new DEPEX opcode. EFI_DEP_REPLACE_TRUE should be
///                        defined to a new value that is not conflicting with PI spec.
///
#define EFI_DEP_REPLACE_TRUE  0xff

///
/// Define the initial size of the dependency expression evaluation stack
///
#define DEPEX_STACK_SIZE_INCREMENT  0x1000

typedef struct {
  EFI_GUID     *ProtocolGuid;
  VOID         **Protocol;
  EFI_EVENT    Event;
  VOID         *Registration;
  BOOLEAN      Present;
} EFI_CORE_PROTOCOL_NOTIFY_ENTRY;

//
// DXE Dispatcher Data structures
//

#define KNOWN_HANDLE_SIGNATURE  SIGNATURE_32('k','n','o','w')
typedef struct {
  UINTN         Signature;
  LIST_ENTRY    Link;           // mFvHandleList
  EFI_HANDLE    Handle;
  EFI_GUID      FvNameGuid;
} KNOWN_HANDLE;

#define EFI_CORE_DRIVER_ENTRY_SIGNATURE  SIGNATURE_32('d','r','v','r')
typedef struct {
  UINTN                            Signature;
  LIST_ENTRY                       Link;            // mDriverList

  LIST_ENTRY                       ScheduledLink;   // mScheduledQueue

  EFI_HANDLE                       FvHandle;
  EFI_GUID                         FileName;
  EFI_DEVICE_PATH_PROTOCOL         *FvFileDevicePath;
  EFI_FIRMWARE_VOLUME2_PROTOCOL    *Fv;

  VOID                             *Depex;
  UINTN                            DepexSize;

  BOOLEAN                          Before;
  BOOLEAN                          After;
  EFI_GUID                         BeforeAfterGuid;

  BOOLEAN                          Dependent;
  BOOLEAN                          Unrequested;
  BOOLEAN                          Scheduled;
  BOOLEAN                          Untrusted;
  BOOLEAN                          Initialized;
  BOOLEAN                          DepexProtocolError;

  EFI_HANDLE                       ImageHandle;
  BOOLEAN                          IsFvImage;
} EFI_CORE_DRIVER_ENTRY;

//
// The data structure of GCD memory map entry
//
#define EFI_GCD_MAP_SIGNATURE  SIGNATURE_32('g','c','d','m')
typedef struct {
  UINTN                   Signature;
  LIST_ENTRY              Link;
  EFI_PHYSICAL_ADDRESS    BaseAddress;
  UINT64                  EndAddress;
  UINT64                  Capabilities;
  UINT64                  Attributes;
  EFI_GCD_MEMORY_TYPE     GcdMemoryType;
  EFI_GCD_IO_TYPE         GcdIoType;
  EFI_HANDLE              ImageHandle;
  EFI_HANDLE              DeviceHandle;
} EFI_GCD_MAP_ENTRY;

#define LOADED_IMAGE_PRIVATE_DATA_SIGNATURE  SIGNATURE_32('l','d','r','i')

typedef struct {
  UINTN                                   Signature;
  /// Image handle
  EFI_HANDLE                              Handle;
  /// Image type
  UINTN                                   Type;
  /// If entrypoint has been called
  BOOLEAN                                 Started;
  /// The image's entry point
  EFI_IMAGE_ENTRY_POINT                   EntryPoint;
  /// loaded image protocol
  EFI_LOADED_IMAGE_PROTOCOL               Info;
  /// Location in memory
  EFI_PHYSICAL_ADDRESS                    ImageBasePage;
  /// Number of pages
  UINTN                                   NumberOfPages;
  /// Original fixup data
  CHAR8                                   *FixupData;
  /// Tpl of started image
  EFI_TPL                                 Tpl;
  /// Status returned by started image
  EFI_STATUS                              Status;
  /// Size of ExitData from started image
  UINTN                                   ExitDataSize;
  /// Pointer to exit data from started image
  VOID                                    *ExitData;
  /// Pointer to pool allocation for context save/restore
  VOID                                    *JumpBuffer;
  /// Pointer to buffer for context save/restore
  BASE_LIBRARY_JUMP_BUFFER                *JumpContext;
  /// Machine type from PE image
  UINT16                                  Machine;
  /// PE/COFF Image Emulator Protocol pointer
  EDKII_PECOFF_IMAGE_EMULATOR_PROTOCOL    *PeCoffEmu;
  /// Runtime image list
  EFI_RUNTIME_IMAGE_ENTRY                 *RuntimeData;
  /// Pointer to Loaded Image Device Path Protocol
  EFI_DEVICE_PATH_PROTOCOL                *LoadedImageDevicePath;
  /// PeCoffLoader ImageContext
  PE_COFF_LOADER_IMAGE_CONTEXT            ImageContext;
  /// Status returned by LoadImage() service.
  EFI_STATUS                              LoadImageStatus;
} LOADED_IMAGE_PRIVATE_DATA;

#define LOADED_IMAGE_PRIVATE_DATA_FROM_THIS(a) \
          CR(a, LOADED_IMAGE_PRIVATE_DATA, Info, LOADED_IMAGE_PRIVATE_DATA_SIGNATURE)

//
// DXE Core Global Variables
//
extern EFI_SYSTEM_TABLE      *gDxeCoreST;
extern EFI_RUNTIME_SERVICES  *gDxeCoreRT;
extern EFI_DXE_SERVICES      *gDxeCoreDS;
extern EFI_HANDLE            gDxeCoreImageHandle;

extern BOOLEAN  gMemoryMapTerminated;

extern EFI_DECOMPRESS_PROTOCOL  gEfiDecompress;

extern EFI_RUNTIME_ARCH_PROTOCOL         *gRuntime;
extern EFI_CPU_ARCH_PROTOCOL             *gCpu;
extern EFI_WATCHDOG_TIMER_ARCH_PROTOCOL  *gWatchdogTimer;
extern EFI_METRONOME_ARCH_PROTOCOL       *gMetronome;
extern EFI_TIMER_ARCH_PROTOCOL           *gTimer;
extern EFI_SECURITY_ARCH_PROTOCOL        *gSecurity;
extern EFI_SECURITY2_ARCH_PROTOCOL       *gSecurity2;
extern EFI_BDS_ARCH_PROTOCOL             *gBds;
extern EFI_SMM_BASE2_PROTOCOL            *gSmmBase2;

extern EFI_TPL  gEfiCurrentTpl;

extern EFI_GUID                   *gDxeCoreFileName;
extern EFI_LOADED_IMAGE_PROTOCOL  *gDxeCoreLoadedImage;

extern EFI_MEMORY_TYPE_INFORMATION  gMemoryTypeInformation[EfiMaxMemoryType + 1];

extern BOOLEAN                    gDispatcherRunning;
extern EFI_RUNTIME_ARCH_PROTOCOL  gRuntimeTemplate;

extern BOOLEAN  gMemoryAttributesTableForwardCfi;

extern EFI_LOAD_FIXED_ADDRESS_CONFIGURATION_TABLE  gLoadModuleAtFixAddressConfigurationTable;
extern BOOLEAN                                     gLoadFixedAddressCodeMemoryReady;
//
// Service Initialization Functions
//

/**
  Called to initialize the pool.

**/
VOID
CoreInitializePool (
  VOID
  );

VOID
CoreSetMemoryTypeInformationRange (
  IN EFI_PHYSICAL_ADDRESS  Start,
  IN UINT64                Length
  );

/**
  Called to initialize the memory map and add descriptors to
  the current descriptor list.
  The first descriptor that is added must be general usable
  memory as the addition allocates heap.

  @param  Type                   The type of memory to add
  @param  Start                  The starting address in the memory range Must be
                                 page aligned
  @param  NumberOfPages          The number of pages in the range
  @param  Attribute              Attributes of the memory to add

  @return None.  The range is added to the memory map

**/
VOID
CoreAddMemoryDescriptor (
  IN EFI_MEMORY_TYPE       Type,
  IN EFI_PHYSICAL_ADDRESS  Start,
  IN UINT64                NumberOfPages,
  IN UINT64                Attribute
  );

/**
  Release memory lock on mGcdMemorySpaceLock.

**/
VOID
CoreReleaseGcdMemoryLock (
  VOID
  );

/**
  Acquire memory lock on mGcdMemorySpaceLock.

**/
VOID
CoreAcquireGcdMemoryLock (
  VOID
  );

/**
  External function. Initializes memory services based on the memory
  descriptor HOBs.  This function is responsible for priming the memory
  map, so memory allocations and resource allocations can be made.
  The first part of this function can not depend on any memory services
  until at least one memory descriptor is provided to the memory services.

  @param  HobStart               The start address of the HOB.
  @param  MemoryBaseAddress      Start address of memory region found to init DXE
                                 core.
  @param  MemoryLength           Length of memory region found to init DXE core.

  @retval EFI_SUCCESS            Memory services successfully initialized.

**/
EFI_STATUS
CoreInitializeMemoryServices (
  IN  VOID                  **HobStart,
  OUT EFI_PHYSICAL_ADDRESS  *MemoryBaseAddress,
  OUT UINT64                *MemoryLength
  );

/**
  External function. Initializes the GCD and memory services based on the memory
  descriptor HOBs.  This function is responsible for priming the GCD map and the
  memory map, so memory allocations and resource allocations can be made. The
  HobStart will be relocated to a pool buffer.

  @param  HobStart               The start address of the HOB
  @param  MemoryBaseAddress      Start address of memory region found to init DXE
                                 core.
  @param  MemoryLength           Length of memory region found to init DXE core.

  @retval EFI_SUCCESS            GCD services successfully initialized.

**/
EFI_STATUS
CoreInitializeGcdServices (
  IN OUT VOID              **HobStart,
  IN EFI_PHYSICAL_ADDRESS  MemoryBaseAddress,
  IN UINT64                MemoryLength
  );

/**
  Initializes "event" support.

  @retval EFI_SUCCESS            Always return success

**/
EFI_STATUS
CoreInitializeEventServices (
  VOID
  );

/**
  Add the Image Services to EFI Boot Services Table and install the protocol
  interfaces for this image.

  @param  HobStart                The HOB to initialize

  @return Status code.

**/
EFI_STATUS
CoreInitializeImageServices (
  IN  VOID  *HobStart
  );

/**
  Creates an event that is fired everytime a Protocol of a specific type is installed.

**/
VOID
CoreNotifyOnProtocolInstallation (
  VOID
  );

/**
  Return TRUE if all AP services are available.

  @retval EFI_SUCCESS    All AP services are available
  @retval EFI_NOT_FOUND  At least one AP service is not available

**/
EFI_STATUS
CoreAllEfiServicesAvailable (
  VOID
  );

/**
  Calcualte the 32-bit CRC in a EFI table using the service provided by the
  gRuntime service.

  @param  Hdr                    Pointer to an EFI standard header

**/
VOID
CalculateEfiHdrCrc (
  IN  OUT EFI_TABLE_HEADER  *Hdr
  );

/**
  Called by the platform code to process a tick.

  @param  Duration               The number of 100ns elapsed since the last call
                                 to TimerTick

**/
VOID
EFIAPI
CoreTimerTick (
  IN UINT64  Duration
  );

/**
  Initialize the dispatcher. Initialize the notification function that runs when
  an FV2 protocol is added to the system.

**/
VOID
CoreInitializeDispatcher (
  VOID
  );

/**
  This is the POSTFIX version of the dependency evaluator.  This code does
  not need to handle Before or After, as it is not valid to call this
  routine in this case. The SOR is just ignored and is a nop in the grammer.
  POSTFIX means all the math is done on top of the stack.

  @param  DriverEntry           DriverEntry element to update.

  @retval TRUE                  If driver is ready to run.
  @retval FALSE                 If driver is not ready to run or some fatal error
                                was found.

**/
BOOLEAN
CoreIsSchedulable (
  IN  EFI_CORE_DRIVER_ENTRY  *DriverEntry
  );

/**
  Preprocess dependency expression and update DriverEntry to reflect the
  state of  Before, After, and SOR dependencies. If DriverEntry->Before
  or DriverEntry->After is set it will never be cleared. If SOR is set
  it will be cleared by CoreSchedule(), and then the driver can be
  dispatched.

  @param  DriverEntry           DriverEntry element to update .

  @retval EFI_SUCCESS           It always works.

**/
EFI_STATUS
CorePreProcessDepex (
  IN  EFI_CORE_DRIVER_ENTRY  *DriverEntry
  );

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
  );

/**
  Make sure the memory map is following all the construction rules,
  it is the last time to check memory map error before exit boot services.

  @param  MapKey                 Memory map key

  @retval EFI_INVALID_PARAMETER  Memory map not consistent with construction
                                 rules.
  @retval EFI_SUCCESS            Valid memory map.

**/
EFI_STATUS
CoreTerminateMemoryMap (
  IN UINTN  MapKey
  );

/**
  Signals all events in the EventGroup.

  @param  EventGroup             The list to signal

**/
VOID
CoreNotifySignalList (
  IN EFI_GUID  *EventGroup
  );

/**
  Boot Service called to add, modify, or remove a system configuration table from
  the EFI System Table.

  @param  Guid           Pointer to the GUID for the entry to add, update, or
                         remove
  @param  Table          Pointer to the configuration table for the entry to add,
                         update, or remove, may be NULL.

  @return EFI_SUCCESS               Guid, Table pair added, updated, or removed.
  @return EFI_INVALID_PARAMETER     Input GUID not valid.
  @return EFI_NOT_FOUND             Attempted to delete non-existant entry
  @return EFI_OUT_OF_RESOURCES      Not enough memory available

**/
EFI_STATUS
EFIAPI
CoreInstallConfigurationTable (
  IN EFI_GUID  *Guid,
  IN VOID      *Table
  );

/**
  Raise the task priority level to the new level.
  High level is implemented by disabling processor interrupts.

  @param  NewTpl  New task priority level

  @return The previous task priority level

**/
EFI_TPL
EFIAPI
CoreRaiseTpl (
  IN EFI_TPL  NewTpl
  );

/**
  Lowers the task priority to the previous value.   If the new
  priority unmasks events at a higher priority, they are dispatched.

  @param  NewTpl  New, lower, task priority

**/
VOID
EFIAPI
CoreRestoreTpl (
  IN EFI_TPL  NewTpl
  );

/**
  Introduces a fine-grained stall.

  @param  Microseconds           The number of microseconds to stall execution.

  @retval EFI_SUCCESS            Execution was stalled for at least the requested
                                 amount of microseconds.
  @retval EFI_NOT_AVAILABLE_YET  gMetronome is not available yet

**/
EFI_STATUS
EFIAPI
CoreStall (
  IN UINTN  Microseconds
  );

/**
  Sets the system's watchdog timer.

  @param  Timeout         The number of seconds to set the watchdog timer to.
                          A value of zero disables the timer.
  @param  WatchdogCode    The numeric code to log on a watchdog timer timeout
                          event. The firmware reserves codes 0x0000 to 0xFFFF.
                          Loaders and operating systems may use other timeout
                          codes.
  @param  DataSize        The size, in bytes, of WatchdogData.
  @param  WatchdogData    A data buffer that includes a Null-terminated Unicode
                          string, optionally followed by additional binary data.
                          The string is a description that the call may use to
                          further indicate the reason to be logged with a
                          watchdog event.

  @return EFI_SUCCESS               Timeout has been set
  @return EFI_NOT_AVAILABLE_YET     WatchdogTimer is not available yet
  @return EFI_UNSUPPORTED           System does not have a timer (currently not used)
  @return EFI_DEVICE_ERROR          Could not complete due to hardware error

**/
EFI_STATUS
EFIAPI
CoreSetWatchdogTimer (
  IN UINTN   Timeout,
  IN UINT64  WatchdogCode,
  IN UINTN   DataSize,
  IN CHAR16  *WatchdogData OPTIONAL
  );

/**
  Wrapper function to CoreInstallProtocolInterfaceNotify.  This is the public API which
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
CoreInstallProtocolInterface (
  IN OUT EFI_HANDLE      *UserHandle,
  IN EFI_GUID            *Protocol,
  IN EFI_INTERFACE_TYPE  InterfaceType,
  IN VOID                *Interface
  );

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
CoreInstallProtocolInterfaceNotify (
  IN OUT EFI_HANDLE      *UserHandle,
  IN EFI_GUID            *Protocol,
  IN EFI_INTERFACE_TYPE  InterfaceType,
  IN VOID                *Interface,
  IN BOOLEAN             Notify
  );

/**
  Installs a list of protocol interface into the boot services environment.
  This function calls InstallProtocolInterface() in a loop. If any error
  occures all the protocols added by this function are removed. This is
  basically a lib function to save space.

  @param  Handle                 The handle to install the protocol handlers on,
                                 or NULL if a new handle is to be allocated
  @param  ...                    EFI_GUID followed by protocol instance. A NULL
                                 terminates the  list. The pairs are the
                                 arguments to InstallProtocolInterface(). All the
                                 protocols are added to Handle.

  @retval EFI_SUCCESS            All the protocol interface was installed.
  @retval EFI_OUT_OF_RESOURCES   There was not enough memory in pool to install all the protocols.
  @retval EFI_ALREADY_STARTED    A Device Path Protocol instance was passed in that is already present in
                                 the handle database.
  @retval EFI_INVALID_PARAMETER  Handle is NULL.
  @retval EFI_INVALID_PARAMETER  Protocol is already installed on the handle specified by Handle.

**/
EFI_STATUS
EFIAPI
CoreInstallMultipleProtocolInterfaces (
  IN OUT EFI_HANDLE  *Handle,
  ...
  );

/**
  Uninstalls a list of protocol interface in the boot services environment.
  This function calls UnisatllProtocolInterface() in a loop. This is
  basically a lib function to save space.

  @param  Handle                 The handle to uninstall the protocol
  @param  ...                    EFI_GUID followed by protocol instance. A NULL
                                 terminates the  list. The pairs are the
                                 arguments to UninstallProtocolInterface(). All
                                 the protocols are added to Handle.

  @return Status code

**/
EFI_STATUS
EFIAPI
CoreUninstallMultipleProtocolInterfaces (
  IN EFI_HANDLE  Handle,
  ...
  );

/**
  Reinstall a protocol interface on a device handle.  The OldInterface for Protocol is replaced by the NewInterface.

  @param  UserHandle             Handle on which the interface is to be
                                 reinstalled
  @param  Protocol               The numeric ID of the interface
  @param  OldInterface           A pointer to the old interface
  @param  NewInterface           A pointer to the new interface

  @retval EFI_SUCCESS            The protocol interface was installed
  @retval EFI_NOT_FOUND          The OldInterface on the handle was not found
  @retval EFI_INVALID_PARAMETER  One of the parameters has an invalid value

**/
EFI_STATUS
EFIAPI
CoreReinstallProtocolInterface (
  IN EFI_HANDLE  UserHandle,
  IN EFI_GUID    *Protocol,
  IN VOID        *OldInterface,
  IN VOID        *NewInterface
  );

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
CoreUninstallProtocolInterface (
  IN EFI_HANDLE  UserHandle,
  IN EFI_GUID    *Protocol,
  IN VOID        *Interface
  );

/**
  Queries a handle to determine if it supports a specified protocol.

  @param  UserHandle             The handle being queried.
  @param  Protocol               The published unique identifier of the protocol.
  @param  Interface              Supplies the address where a pointer to the
                                 corresponding Protocol Interface is returned.

  @return The requested protocol interface for the handle

**/
EFI_STATUS
EFIAPI
CoreHandleProtocol (
  IN EFI_HANDLE  UserHandle,
  IN EFI_GUID    *Protocol,
  OUT VOID       **Interface
  );

/**
  Locates the installed protocol handler for the handle, and
  invokes it to obtain the protocol interface. Usage information
  is registered in the protocol data base.

  @param  UserHandle             The handle to obtain the protocol interface on
  @param  Protocol               The ID of the protocol
  @param  Interface              The location to return the protocol interface
  @param  ImageHandle            The handle of the Image that is opening the
                                 protocol interface specified by Protocol and
                                 Interface.
  @param  ControllerHandle       The controller handle that is requiring this
                                 interface.
  @param  Attributes             The open mode of the protocol interface
                                 specified by Handle and Protocol.

  @retval EFI_INVALID_PARAMETER  Protocol is NULL.
  @retval EFI_SUCCESS            Get the protocol interface.

**/
EFI_STATUS
EFIAPI
CoreOpenProtocol (
  IN  EFI_HANDLE  UserHandle,
  IN  EFI_GUID    *Protocol,
  OUT VOID        **Interface OPTIONAL,
  IN  EFI_HANDLE  ImageHandle,
  IN  EFI_HANDLE  ControllerHandle,
  IN  UINT32      Attributes
  );

/**
  Return information about Opened protocols in the system

  @param  UserHandle             The handle to close the protocol interface on
  @param  Protocol               The ID of the protocol
  @param  EntryBuffer            A pointer to a buffer of open protocol
                                 information in the form of
                                 EFI_OPEN_PROTOCOL_INFORMATION_ENTRY structures.
  @param  EntryCount             Number of EntryBuffer entries

**/
EFI_STATUS
EFIAPI
CoreOpenProtocolInformation (
  IN  EFI_HANDLE                           UserHandle,
  IN  EFI_GUID                             *Protocol,
  OUT EFI_OPEN_PROTOCOL_INFORMATION_ENTRY  **EntryBuffer,
  OUT UINTN                                *EntryCount
  );

/**
  Closes a protocol on a handle that was opened using OpenProtocol().

  @param  UserHandle             The handle for the protocol interface that was
                                 previously opened with OpenProtocol(), and is
                                 now being closed.
  @param  Protocol               The published unique identifier of the protocol.
                                 It is the caller's responsibility to pass in a
                                 valid GUID.
  @param  AgentHandle            The handle of the agent that is closing the
                                 protocol interface.
  @param  ControllerHandle       If the agent that opened a protocol is a driver
                                 that follows the EFI Driver Model, then this
                                 parameter is the controller handle that required
                                 the protocol interface. If the agent does not
                                 follow the EFI Driver Model, then this parameter
                                 is optional and may be NULL.

  @retval EFI_SUCCESS            The protocol instance was closed.
  @retval EFI_INVALID_PARAMETER  Handle, AgentHandle or ControllerHandle is not a
                                 valid EFI_HANDLE.
  @retval EFI_NOT_FOUND          Can not find the specified protocol or
                                 AgentHandle.

**/
EFI_STATUS
EFIAPI
CoreCloseProtocol (
  IN  EFI_HANDLE  UserHandle,
  IN  EFI_GUID    *Protocol,
  IN  EFI_HANDLE  AgentHandle,
  IN  EFI_HANDLE  ControllerHandle
  );

/**
  Retrieves the list of protocol interface GUIDs that are installed on a handle in a buffer allocated
  from pool.

  @param  UserHandle             The handle from which to retrieve the list of
                                 protocol interface GUIDs.
  @param  ProtocolBuffer         A pointer to the list of protocol interface GUID
                                 pointers that are installed on Handle.
  @param  ProtocolBufferCount    A pointer to the number of GUID pointers present
                                 in ProtocolBuffer.

  @retval EFI_SUCCESS            The list of protocol interface GUIDs installed
                                 on Handle was returned in ProtocolBuffer. The
                                 number of protocol interface GUIDs was returned
                                 in ProtocolBufferCount.
  @retval EFI_INVALID_PARAMETER  Handle is NULL.
  @retval EFI_INVALID_PARAMETER  Handle is not a valid EFI_HANDLE.
  @retval EFI_INVALID_PARAMETER  ProtocolBuffer is NULL.
  @retval EFI_INVALID_PARAMETER  ProtocolBufferCount is NULL.
  @retval EFI_OUT_OF_RESOURCES   There is not enough pool memory to store the
                                 results.

**/
EFI_STATUS
EFIAPI
CoreProtocolsPerHandle (
  IN EFI_HANDLE  UserHandle,
  OUT EFI_GUID   ***ProtocolBuffer,
  OUT UINTN      *ProtocolBufferCount
  );

/**
  Add a new protocol notification record for the request protocol.

  @param  Protocol               The requested protocol to add the notify
                                 registration
  @param  Event                  The event to signal
  @param  Registration           Returns the registration record

  @retval EFI_INVALID_PARAMETER  Invalid parameter
  @retval EFI_SUCCESS            Successfully returned the registration record
                                 that has been added

**/
EFI_STATUS
EFIAPI
CoreRegisterProtocolNotify (
  IN EFI_GUID   *Protocol,
  IN EFI_EVENT  Event,
  OUT  VOID     **Registration
  );

/**
  Removes all the events in the protocol database that match Event.

  @param  Event                  The event to search for in the protocol
                                 database.

  @return EFI_SUCCESS when done searching the entire database.

**/
EFI_STATUS
CoreUnregisterProtocolNotify (
  IN EFI_EVENT  Event
  );

/**
  Locates the requested handle(s) and returns them in Buffer.

  @param  SearchType             The type of search to perform to locate the
                                 handles
  @param  Protocol               The protocol to search for
  @param  SearchKey              Dependant on SearchType
  @param  BufferSize             On input the size of Buffer.  On output the
                                 size of data returned.
  @param  Buffer                 The buffer to return the results in

  @retval EFI_BUFFER_TOO_SMALL   Buffer too small, required buffer size is
                                 returned in BufferSize.
  @retval EFI_INVALID_PARAMETER  Invalid parameter
  @retval EFI_SUCCESS            Successfully found the requested handle(s) and
                                 returns them in Buffer.

**/
EFI_STATUS
EFIAPI
CoreLocateHandle (
  IN EFI_LOCATE_SEARCH_TYPE  SearchType,
  IN EFI_GUID                *Protocol   OPTIONAL,
  IN VOID                    *SearchKey  OPTIONAL,
  IN OUT UINTN               *BufferSize,
  OUT EFI_HANDLE             *Buffer
  );

/**
  Locates the handle to a device on the device path that best matches the specified protocol.

  @param  Protocol               The protocol to search for.
  @param  DevicePath             On input, a pointer to a pointer to the device
                                 path. On output, the device path pointer is
                                 modified to point to the remaining part of the
                                 devicepath.
  @param  Device                 A pointer to the returned device handle.

  @retval EFI_SUCCESS            The resulting handle was returned.
  @retval EFI_NOT_FOUND          No handles matched the search.
  @retval EFI_INVALID_PARAMETER  One of the parameters has an invalid value.

**/
EFI_STATUS
EFIAPI
CoreLocateDevicePath (
  IN EFI_GUID                      *Protocol,
  IN OUT EFI_DEVICE_PATH_PROTOCOL  **DevicePath,
  OUT EFI_HANDLE                   *Device
  );

/**
  Function returns an array of handles that support the requested protocol
  in a buffer allocated from pool. This is a version of CoreLocateHandle()
  that allocates a buffer for the caller.

  @param  SearchType             Specifies which handle(s) are to be returned.
  @param  Protocol               Provides the protocol to search by.    This
                                 parameter is only valid for SearchType
                                 ByProtocol.
  @param  SearchKey              Supplies the search key depending on the
                                 SearchType.
  @param  NumberHandles          The number of handles returned in Buffer.
  @param  Buffer                 A pointer to the buffer to return the requested
                                 array of  handles that support Protocol.

  @retval EFI_SUCCESS            The result array of handles was returned.
  @retval EFI_NOT_FOUND          No handles match the search.
  @retval EFI_OUT_OF_RESOURCES   There is not enough pool memory to store the
                                 matching results.
  @retval EFI_INVALID_PARAMETER  One or more parameters are not valid.

**/
EFI_STATUS
EFIAPI
CoreLocateHandleBuffer (
  IN EFI_LOCATE_SEARCH_TYPE  SearchType,
  IN EFI_GUID                *Protocol OPTIONAL,
  IN VOID                    *SearchKey OPTIONAL,
  IN OUT UINTN               *NumberHandles,
  OUT EFI_HANDLE             **Buffer
  );

/**
  Return the first Protocol Interface that matches the Protocol GUID. If
  Registration is passed in, return a Protocol Instance that was just add
  to the system. If Registration is NULL return the first Protocol Interface
  you find.

  @param  Protocol               The protocol to search for
  @param  Registration           Optional Registration Key returned from
                                 RegisterProtocolNotify()
  @param  Interface              Return the Protocol interface (instance).

  @retval EFI_SUCCESS            If a valid Interface is returned
  @retval EFI_INVALID_PARAMETER  Invalid parameter
  @retval EFI_NOT_FOUND          Protocol interface not found

**/
EFI_STATUS
EFIAPI
CoreLocateProtocol (
  IN  EFI_GUID  *Protocol,
  IN  VOID      *Registration OPTIONAL,
  OUT VOID      **Interface
  );

/**
  return handle database key.


  @return Handle database key.

**/
UINT64
CoreGetHandleDatabaseKey (
  VOID
  );

/**
  Go connect any handles that were created or modified while a image executed.

  @param  Key                    The Key to show that the handle has been
                                 created/modified

**/
VOID
CoreConnectHandlesByKey (
  UINT64  Key
  );

/**
  Connects one or more drivers to a controller.

  @param  ControllerHandle      The handle of the controller to which driver(s) are to be connected.
  @param  DriverImageHandle     A pointer to an ordered list handles that support the
                                EFI_DRIVER_BINDING_PROTOCOL.
  @param  RemainingDevicePath   A pointer to the device path that specifies a child of the
                                controller specified by ControllerHandle.
  @param  Recursive             If TRUE, then ConnectController() is called recursively
                                until the entire tree of controllers below the controller specified
                                by ControllerHandle have been created. If FALSE, then
                                the tree of controllers is only expanded one level.

  @retval EFI_SUCCESS           1) One or more drivers were connected to ControllerHandle.
                                2) No drivers were connected to ControllerHandle, but
                                RemainingDevicePath is not NULL, and it is an End Device
                                Path Node.
  @retval EFI_INVALID_PARAMETER ControllerHandle is NULL.
  @retval EFI_NOT_FOUND         1) There are no EFI_DRIVER_BINDING_PROTOCOL instances
                                present in the system.
                                2) No drivers were connected to ControllerHandle.
  @retval EFI_SECURITY_VIOLATION
                                The user has no permission to start UEFI device drivers on the device path
                                associated with the ControllerHandle or specified by the RemainingDevicePath.

**/
EFI_STATUS
EFIAPI
CoreConnectController (
  IN  EFI_HANDLE                ControllerHandle,
  IN  EFI_HANDLE                *DriverImageHandle    OPTIONAL,
  IN  EFI_DEVICE_PATH_PROTOCOL  *RemainingDevicePath  OPTIONAL,
  IN  BOOLEAN                   Recursive
  );

/**
  Disonnects a controller from a driver

  @param  ControllerHandle                      ControllerHandle The handle of
                                                the controller from which
                                                driver(s)  are to be
                                                disconnected.
  @param  DriverImageHandle                     DriverImageHandle The driver to
                                                disconnect from ControllerHandle.
  @param  ChildHandle                           ChildHandle The handle of the
                                                child to destroy.

  @retval EFI_SUCCESS                           One or more drivers were
                                                disconnected from the controller.
  @retval EFI_SUCCESS                           On entry, no drivers are managing
                                                ControllerHandle.
  @retval EFI_SUCCESS                           DriverImageHandle is not NULL,
                                                and on entry DriverImageHandle is
                                                not managing ControllerHandle.
  @retval EFI_INVALID_PARAMETER                 ControllerHandle is NULL.
  @retval EFI_INVALID_PARAMETER                 DriverImageHandle is not NULL,
                                                and it is not a valid EFI_HANDLE.
  @retval EFI_INVALID_PARAMETER                 ChildHandle is not NULL, and it
                                                is not a valid EFI_HANDLE.
  @retval EFI_OUT_OF_RESOURCES                  There are not enough resources
                                                available to disconnect any
                                                drivers from ControllerHandle.
  @retval EFI_DEVICE_ERROR                      The controller could not be
                                                disconnected because of a device
                                                error.

**/
EFI_STATUS
EFIAPI
CoreDisconnectController (
  IN  EFI_HANDLE  ControllerHandle,
  IN  EFI_HANDLE  DriverImageHandle  OPTIONAL,
  IN  EFI_HANDLE  ChildHandle        OPTIONAL
  );

/**
  Allocates pages from the memory map.

  @param  Type                   The type of allocation to perform
  @param  MemoryType             The type of memory to turn the allocated pages
                                 into
  @param  NumberOfPages          The number of pages to allocate
  @param  Memory                 A pointer to receive the base allocated memory
                                 address

  @return Status. On success, Memory is filled in with the base address allocated
  @retval EFI_INVALID_PARAMETER  Parameters violate checking rules defined in
                                 spec.
  @retval EFI_NOT_FOUND          Could not allocate pages match the requirement.
  @retval EFI_OUT_OF_RESOURCES   No enough pages to allocate.
  @retval EFI_SUCCESS            Pages successfully allocated.

**/
EFI_STATUS
EFIAPI
CoreAllocatePages (
  IN EFI_ALLOCATE_TYPE         Type,
  IN EFI_MEMORY_TYPE           MemoryType,
  IN UINTN                     NumberOfPages,
  IN OUT EFI_PHYSICAL_ADDRESS  *Memory
  );

/**
  Frees previous allocated pages.

  @param  Memory                 Base address of memory being freed
  @param  NumberOfPages          The number of pages to free

  @retval EFI_NOT_FOUND          Could not find the entry that covers the range
  @retval EFI_INVALID_PARAMETER  Address not aligned
  @return EFI_SUCCESS         -Pages successfully freed.

**/
EFI_STATUS
EFIAPI
CoreFreePages (
  IN EFI_PHYSICAL_ADDRESS  Memory,
  IN UINTN                 NumberOfPages
  );

/**
  This function returns a copy of the current memory map. The map is an array of
  memory descriptors, each of which describes a contiguous block of memory.

  @param  MemoryMapSize          A pointer to the size, in bytes, of the
                                 MemoryMap buffer. On input, this is the size of
                                 the buffer allocated by the caller.  On output,
                                 it is the size of the buffer returned by the
                                 firmware  if the buffer was large enough, or the
                                 size of the buffer needed  to contain the map if
                                 the buffer was too small.
  @param  MemoryMap              A pointer to the buffer in which firmware places
                                 the current memory map.
  @param  MapKey                 A pointer to the location in which firmware
                                 returns the key for the current memory map.
  @param  DescriptorSize         A pointer to the location in which firmware
                                 returns the size, in bytes, of an individual
                                 EFI_MEMORY_DESCRIPTOR.
  @param  DescriptorVersion      A pointer to the location in which firmware
                                 returns the version number associated with the
                                 EFI_MEMORY_DESCRIPTOR.

  @retval EFI_SUCCESS            The memory map was returned in the MemoryMap
                                 buffer.
  @retval EFI_BUFFER_TOO_SMALL   The MemoryMap buffer was too small. The current
                                 buffer size needed to hold the memory map is
                                 returned in MemoryMapSize.
  @retval EFI_INVALID_PARAMETER  One of the parameters has an invalid value.

**/
EFI_STATUS
EFIAPI
CoreGetMemoryMap (
  IN OUT UINTN                  *MemoryMapSize,
  IN OUT EFI_MEMORY_DESCRIPTOR  *MemoryMap,
  OUT UINTN                     *MapKey,
  OUT UINTN                     *DescriptorSize,
  OUT UINT32                    *DescriptorVersion
  );

/**
  Allocate pool of a particular type.

  @param  PoolType               Type of pool to allocate
  @param  Size                   The amount of pool to allocate
  @param  Buffer                 The address to return a pointer to the allocated
                                 pool

  @retval EFI_INVALID_PARAMETER  PoolType not valid or Buffer is NULL
  @retval EFI_OUT_OF_RESOURCES   Size exceeds max pool size or allocation failed.
  @retval EFI_SUCCESS            Pool successfully allocated.

**/
EFI_STATUS
EFIAPI
CoreAllocatePool (
  IN EFI_MEMORY_TYPE  PoolType,
  IN UINTN            Size,
  OUT VOID            **Buffer
  );

/**
  Allocate pool of a particular type.

  @param  PoolType               Type of pool to allocate
  @param  Size                   The amount of pool to allocate
  @param  Buffer                 The address to return a pointer to the allocated
                                 pool

  @retval EFI_INVALID_PARAMETER  PoolType not valid or Buffer is NULL
  @retval EFI_OUT_OF_RESOURCES   Size exceeds max pool size or allocation failed.
  @retval EFI_SUCCESS            Pool successfully allocated.

**/
EFI_STATUS
EFIAPI
CoreInternalAllocatePool (
  IN EFI_MEMORY_TYPE  PoolType,
  IN UINTN            Size,
  OUT VOID            **Buffer
  );

/**
  Frees pool.

  @param  Buffer                 The allocated pool entry to free

  @retval EFI_INVALID_PARAMETER  Buffer is not a valid value.
  @retval EFI_SUCCESS            Pool successfully freed.

**/
EFI_STATUS
EFIAPI
CoreFreePool (
  IN VOID  *Buffer
  );

/**
  Frees pool.

  @param  Buffer                 The allocated pool entry to free
  @param  PoolType               Pointer to pool type

  @retval EFI_INVALID_PARAMETER  Buffer is not a valid value.
  @retval EFI_SUCCESS            Pool successfully freed.

**/
EFI_STATUS
EFIAPI
CoreInternalFreePool (
  IN VOID              *Buffer,
  OUT EFI_MEMORY_TYPE  *PoolType OPTIONAL
  );

/**
  Loads an EFI image into memory and returns a handle to the image.

  @param  BootPolicy              If TRUE, indicates that the request originates
                                  from the boot manager, and that the boot
                                  manager is attempting to load FilePath as a
                                  boot selection.
  @param  ParentImageHandle       The caller's image handle.
  @param  FilePath                The specific file path from which the image is
                                  loaded.
  @param  SourceBuffer            If not NULL, a pointer to the memory location
                                  containing a copy of the image to be loaded.
  @param  SourceSize              The size in bytes of SourceBuffer.
  @param  ImageHandle             Pointer to the returned image handle that is
                                  created when the image is successfully loaded.

  @retval EFI_SUCCESS             The image was loaded into memory.
  @retval EFI_NOT_FOUND           The FilePath was not found.
  @retval EFI_INVALID_PARAMETER   One of the parameters has an invalid value.
  @retval EFI_UNSUPPORTED         The image type is not supported, or the device
                                  path cannot be parsed to locate the proper
                                  protocol for loading the file.
  @retval EFI_OUT_OF_RESOURCES    Image was not loaded due to insufficient
                                  resources.
  @retval EFI_LOAD_ERROR          Image was not loaded because the image format was corrupt or not
                                  understood.
  @retval EFI_DEVICE_ERROR        Image was not loaded because the device returned a read error.
  @retval EFI_ACCESS_DENIED       Image was not loaded because the platform policy prohibits the
                                  image from being loaded. NULL is returned in *ImageHandle.
  @retval EFI_SECURITY_VIOLATION  Image was loaded and an ImageHandle was created with a
                                  valid EFI_LOADED_IMAGE_PROTOCOL. However, the current
                                  platform policy specifies that the image should not be started.

**/
EFI_STATUS
EFIAPI
CoreLoadImage (
  IN BOOLEAN                   BootPolicy,
  IN EFI_HANDLE                ParentImageHandle,
  IN EFI_DEVICE_PATH_PROTOCOL  *FilePath,
  IN VOID                      *SourceBuffer   OPTIONAL,
  IN UINTN                     SourceSize,
  OUT EFI_HANDLE               *ImageHandle
  );

/**
  Unloads an image.

  @param  ImageHandle             Handle that identifies the image to be
                                  unloaded.

  @retval EFI_SUCCESS             The image has been unloaded.
  @retval EFI_UNSUPPORTED         The image has been started, and does not support
                                  unload.
  @retval EFI_INVALID_PARAMPETER  ImageHandle is not a valid image handle.

**/
EFI_STATUS
EFIAPI
CoreUnloadImage (
  IN EFI_HANDLE  ImageHandle
  );

/**
  Transfer control to a loaded image's entry point.

  @param  ImageHandle             Handle of image to be started.
  @param  ExitDataSize            Pointer of the size to ExitData
  @param  ExitData                Pointer to a pointer to a data buffer that
                                  includes a Null-terminated string,
                                  optionally followed by additional binary data.
                                  The string is a description that the caller may
                                  use to further indicate the reason for the
                                  image's exit.

  @retval EFI_INVALID_PARAMETER   Invalid parameter
  @retval EFI_OUT_OF_RESOURCES    No enough buffer to allocate
  @retval EFI_SECURITY_VIOLATION  The current platform policy specifies that the image should not be started.
  @retval EFI_SUCCESS             Successfully transfer control to the image's
                                  entry point.

**/
EFI_STATUS
EFIAPI
CoreStartImage (
  IN EFI_HANDLE  ImageHandle,
  OUT UINTN      *ExitDataSize,
  OUT CHAR16     **ExitData  OPTIONAL
  );

/**
  Terminates the currently loaded EFI image and returns control to boot services.

  @param  ImageHandle             Handle that identifies the image. This
                                  parameter is passed to the image on entry.
  @param  Status                  The image's exit code.
  @param  ExitDataSize            The size, in bytes, of ExitData. Ignored if
                                  ExitStatus is EFI_SUCCESS.
  @param  ExitData                Pointer to a data buffer that includes a
                                  Null-terminated Unicode string, optionally
                                  followed by additional binary data. The string
                                  is a description that the caller may use to
                                  further indicate the reason for the image's
                                  exit.

  @retval EFI_INVALID_PARAMETER   Image handle is NULL or it is not current
                                  image.
  @retval EFI_SUCCESS             Successfully terminates the currently loaded
                                  EFI image.
  @retval EFI_ACCESS_DENIED       Should never reach there.
  @retval EFI_OUT_OF_RESOURCES    Could not allocate pool

**/
EFI_STATUS
EFIAPI
CoreExit (
  IN EFI_HANDLE  ImageHandle,
  IN EFI_STATUS  Status,
  IN UINTN       ExitDataSize,
  IN CHAR16      *ExitData  OPTIONAL
  );

/**
  Creates an event.

  @param  Type                   The type of event to create and its mode and
                                 attributes
  @param  NotifyTpl              The task priority level of event notifications
  @param  NotifyFunction         Pointer to the events notification function
  @param  NotifyContext          Pointer to the notification functions context;
                                 corresponds to parameter "Context" in the
                                 notification function
  @param  Event                  Pointer to the newly created event if the call
                                 succeeds; undefined otherwise

  @retval EFI_SUCCESS            The event structure was created
  @retval EFI_INVALID_PARAMETER  One of the parameters has an invalid value
  @retval EFI_OUT_OF_RESOURCES   The event could not be allocated

**/
EFI_STATUS
EFIAPI
CoreCreateEvent (
  IN UINT32            Type,
  IN EFI_TPL           NotifyTpl,
  IN EFI_EVENT_NOTIFY  NotifyFunction  OPTIONAL,
  IN VOID              *NotifyContext  OPTIONAL,
  OUT EFI_EVENT        *Event
  );

/**
  Creates an event in a group.

  @param  Type                   The type of event to create and its mode and
                                 attributes
  @param  NotifyTpl              The task priority level of event notifications
  @param  NotifyFunction         Pointer to the events notification function
  @param  NotifyContext          Pointer to the notification functions context;
                                 corresponds to parameter "Context" in the
                                 notification function
  @param  EventGroup             GUID for EventGroup if NULL act the same as
                                 gBS->CreateEvent().
  @param  Event                  Pointer to the newly created event if the call
                                 succeeds; undefined otherwise

  @retval EFI_SUCCESS            The event structure was created
  @retval EFI_INVALID_PARAMETER  One of the parameters has an invalid value
  @retval EFI_OUT_OF_RESOURCES   The event could not be allocated

**/
EFI_STATUS
EFIAPI
CoreCreateEventEx (
  IN UINT32            Type,
  IN EFI_TPL           NotifyTpl,
  IN EFI_EVENT_NOTIFY  NotifyFunction  OPTIONAL,
  IN CONST VOID        *NotifyContext  OPTIONAL,
  IN CONST EFI_GUID    *EventGroup     OPTIONAL,
  OUT EFI_EVENT        *Event
  );

/**
  Creates a general-purpose event structure

  @param  Type                   The type of event to create and its mode and
                                 attributes
  @param  NotifyTpl              The task priority level of event notifications
  @param  NotifyFunction         Pointer to the events notification function
  @param  NotifyContext          Pointer to the notification functions context;
                                 corresponds to parameter "Context" in the
                                 notification function
  @param  EventGroup             GUID for EventGroup if NULL act the same as
                                 gBS->CreateEvent().
  @param  Event                  Pointer to the newly created event if the call
                                 succeeds; undefined otherwise

  @retval EFI_SUCCESS            The event structure was created
  @retval EFI_INVALID_PARAMETER  One of the parameters has an invalid value
  @retval EFI_OUT_OF_RESOURCES   The event could not be allocated

**/
EFI_STATUS
EFIAPI
CoreCreateEventInternal (
  IN UINT32            Type,
  IN EFI_TPL           NotifyTpl,
  IN EFI_EVENT_NOTIFY  NotifyFunction  OPTIONAL,
  IN CONST VOID        *NotifyContext  OPTIONAL,
  IN CONST EFI_GUID    *EventGroup     OPTIONAL,
  OUT EFI_EVENT        *Event
  );

/**
  Sets the type of timer and the trigger time for a timer event.

  @param  UserEvent              The timer event that is to be signaled at the
                                 specified time
  @param  Type                   The type of time that is specified in
                                 TriggerTime
  @param  TriggerTime            The number of 100ns units until the timer
                                 expires

  @retval EFI_SUCCESS            The event has been set to be signaled at the
                                 requested time
  @retval EFI_INVALID_PARAMETER  Event or Type is not valid

**/
EFI_STATUS
EFIAPI
CoreSetTimer (
  IN EFI_EVENT        UserEvent,
  IN EFI_TIMER_DELAY  Type,
  IN UINT64           TriggerTime
  );

/**
  Signals the event.  Queues the event to be notified if needed.

  @param  UserEvent              The event to signal .

  @retval EFI_INVALID_PARAMETER  Parameters are not valid.
  @retval EFI_SUCCESS            The event was signaled.

**/
EFI_STATUS
EFIAPI
CoreSignalEvent (
  IN EFI_EVENT  UserEvent
  );

/**
  Stops execution until an event is signaled.

  @param  NumberOfEvents         The number of events in the UserEvents array
  @param  UserEvents             An array of EFI_EVENT
  @param  UserIndex              Pointer to the index of the event which
                                 satisfied the wait condition

  @retval EFI_SUCCESS            The event indicated by Index was signaled.
  @retval EFI_INVALID_PARAMETER  The event indicated by Index has a notification
                                 function or Event was not a valid type
  @retval EFI_UNSUPPORTED        The current TPL is not TPL_APPLICATION

**/
EFI_STATUS
EFIAPI
CoreWaitForEvent (
  IN UINTN      NumberOfEvents,
  IN EFI_EVENT  *UserEvents,
  OUT UINTN     *UserIndex
  );

/**
  Closes an event and frees the event structure.

  @param  UserEvent              Event to close

  @retval EFI_INVALID_PARAMETER  Parameters are not valid.
  @retval EFI_SUCCESS            The event has been closed

**/
EFI_STATUS
EFIAPI
CoreCloseEvent (
  IN EFI_EVENT  UserEvent
  );

/**
  Check the status of an event.

  @param  UserEvent              The event to check

  @retval EFI_SUCCESS            The event is in the signaled state
  @retval EFI_NOT_READY          The event is not in the signaled state
  @retval EFI_INVALID_PARAMETER  Event is of type EVT_NOTIFY_SIGNAL

**/
EFI_STATUS
EFIAPI
CoreCheckEvent (
  IN EFI_EVENT  UserEvent
  );

/**
  Adds reserved memory, system memory, or memory-mapped I/O resources to the
  global coherency domain of the processor.

  @param  GcdMemoryType          Memory type of the memory space.
  @param  BaseAddress            Base address of the memory space.
  @param  Length                 Length of the memory space.
  @param  Capabilities           alterable attributes of the memory space.

  @retval EFI_SUCCESS            Merged this memory space into GCD map.

**/
EFI_STATUS
EFIAPI
CoreAddMemorySpace (
  IN EFI_GCD_MEMORY_TYPE   GcdMemoryType,
  IN EFI_PHYSICAL_ADDRESS  BaseAddress,
  IN UINT64                Length,
  IN UINT64                Capabilities
  );

/**
  Allocates nonexistent memory, reserved memory, system memory, or memorymapped
  I/O resources from the global coherency domain of the processor.

  @param  GcdAllocateType        The type of allocate operation
  @param  GcdMemoryType          The desired memory type
  @param  Alignment              Align with 2^Alignment
  @param  Length                 Length to allocate
  @param  BaseAddress            Base address to allocate
  @param  ImageHandle            The image handle consume the allocated space.
  @param  DeviceHandle           The device handle consume the allocated space.

  @retval EFI_INVALID_PARAMETER  Invalid parameter.
  @retval EFI_NOT_FOUND          No descriptor contains the desired space.
  @retval EFI_SUCCESS            Memory space successfully allocated.

**/
EFI_STATUS
EFIAPI
CoreAllocateMemorySpace (
  IN     EFI_GCD_ALLOCATE_TYPE  GcdAllocateType,
  IN     EFI_GCD_MEMORY_TYPE    GcdMemoryType,
  IN     UINTN                  Alignment,
  IN     UINT64                 Length,
  IN OUT EFI_PHYSICAL_ADDRESS   *BaseAddress,
  IN     EFI_HANDLE             ImageHandle,
  IN     EFI_HANDLE             DeviceHandle OPTIONAL
  );

/**
  Frees nonexistent memory, reserved memory, system memory, or memory-mapped
  I/O resources from the global coherency domain of the processor.

  @param  BaseAddress            Base address of the memory space.
  @param  Length                 Length of the memory space.

  @retval EFI_SUCCESS            Space successfully freed.

**/
EFI_STATUS
EFIAPI
CoreFreeMemorySpace (
  IN EFI_PHYSICAL_ADDRESS  BaseAddress,
  IN UINT64                Length
  );

/**
  Removes reserved memory, system memory, or memory-mapped I/O resources from
  the global coherency domain of the processor.

  @param  BaseAddress            Base address of the memory space.
  @param  Length                 Length of the memory space.

  @retval EFI_SUCCESS            Successfully remove a segment of memory space.

**/
EFI_STATUS
EFIAPI
CoreRemoveMemorySpace (
  IN EFI_PHYSICAL_ADDRESS  BaseAddress,
  IN UINT64                Length
  );

/**
  Retrieves the descriptor for a memory region containing a specified address.

  @param  BaseAddress            Specified start address
  @param  Descriptor             Specified length

  @retval EFI_INVALID_PARAMETER  Invalid parameter
  @retval EFI_SUCCESS            Successfully get memory space descriptor.

**/
EFI_STATUS
EFIAPI
CoreGetMemorySpaceDescriptor (
  IN  EFI_PHYSICAL_ADDRESS             BaseAddress,
  OUT EFI_GCD_MEMORY_SPACE_DESCRIPTOR  *Descriptor
  );

/**
  Modifies the attributes for a memory region in the global coherency domain of the
  processor.

  @param  BaseAddress            Specified start address
  @param  Length                 Specified length
  @param  Attributes             Specified attributes

  @retval EFI_SUCCESS           The attributes were set for the memory region.
  @retval EFI_INVALID_PARAMETER Length is zero.
  @retval EFI_UNSUPPORTED       The processor does not support one or more bytes of the memory
                                resource range specified by BaseAddress and Length.
  @retval EFI_UNSUPPORTED       The bit mask of attributes is not support for the memory resource
                                range specified by BaseAddress and Length.
  @retval EFI_ACCESS_DENIED     The attributes for the memory resource range specified by
                                BaseAddress and Length cannot be modified.
  @retval EFI_OUT_OF_RESOURCES  There are not enough system resources to modify the attributes of
                                the memory resource range.
  @retval EFI_NOT_AVAILABLE_YET The attributes cannot be set because CPU architectural protocol is
                                not available yet.

**/
EFI_STATUS
EFIAPI
CoreSetMemorySpaceAttributes (
  IN EFI_PHYSICAL_ADDRESS  BaseAddress,
  IN UINT64                Length,
  IN UINT64                Attributes
  );

/**
  Modifies the capabilities for a memory region in the global coherency domain of the
  processor.

  @param  BaseAddress      The physical address that is the start address of a memory region.
  @param  Length           The size in bytes of the memory region.
  @param  Capabilities     The bit mask of capabilities that the memory region supports.

  @retval EFI_SUCCESS           The capabilities were set for the memory region.
  @retval EFI_INVALID_PARAMETER Length is zero.
  @retval EFI_UNSUPPORTED       The capabilities specified by Capabilities do not include the
                                memory region attributes currently in use.
  @retval EFI_ACCESS_DENIED     The capabilities for the memory resource range specified by
                                BaseAddress and Length cannot be modified.
  @retval EFI_OUT_OF_RESOURCES  There are not enough system resources to modify the capabilities
                                of the memory resource range.
**/
EFI_STATUS
EFIAPI
CoreSetMemorySpaceCapabilities (
  IN EFI_PHYSICAL_ADDRESS  BaseAddress,
  IN UINT64                Length,
  IN UINT64                Capabilities
  );

/**
  Returns a map of the memory resources in the global coherency domain of the
  processor.

  @param  NumberOfDescriptors    Number of descriptors.
  @param  MemorySpaceMap         Descriptor array

  @retval EFI_INVALID_PARAMETER  Invalid parameter
  @retval EFI_OUT_OF_RESOURCES   No enough buffer to allocate
  @retval EFI_SUCCESS            Successfully get memory space map.

**/
EFI_STATUS
EFIAPI
CoreGetMemorySpaceMap (
  OUT UINTN                            *NumberOfDescriptors,
  OUT EFI_GCD_MEMORY_SPACE_DESCRIPTOR  **MemorySpaceMap
  );

/**
  Adds reserved I/O or I/O resources to the global coherency domain of the processor.

  @param  GcdIoType              IO type of the segment.
  @param  BaseAddress            Base address of the segment.
  @param  Length                 Length of the segment.

  @retval EFI_SUCCESS            Merged this segment into GCD map.
  @retval EFI_INVALID_PARAMETER  Parameter not valid

**/
EFI_STATUS
EFIAPI
CoreAddIoSpace (
  IN EFI_GCD_IO_TYPE       GcdIoType,
  IN EFI_PHYSICAL_ADDRESS  BaseAddress,
  IN UINT64                Length
  );

/**
  Allocates nonexistent I/O, reserved I/O, or I/O resources from the global coherency
  domain of the processor.

  @param  GcdAllocateType        The type of allocate operation
  @param  GcdIoType              The desired IO type
  @param  Alignment              Align with 2^Alignment
  @param  Length                 Length to allocate
  @param  BaseAddress            Base address to allocate
  @param  ImageHandle            The image handle consume the allocated space.
  @param  DeviceHandle           The device handle consume the allocated space.

  @retval EFI_INVALID_PARAMETER  Invalid parameter.
  @retval EFI_NOT_FOUND          No descriptor contains the desired space.
  @retval EFI_SUCCESS            IO space successfully allocated.

**/
EFI_STATUS
EFIAPI
CoreAllocateIoSpace (
  IN     EFI_GCD_ALLOCATE_TYPE  GcdAllocateType,
  IN     EFI_GCD_IO_TYPE        GcdIoType,
  IN     UINTN                  Alignment,
  IN     UINT64                 Length,
  IN OUT EFI_PHYSICAL_ADDRESS   *BaseAddress,
  IN     EFI_HANDLE             ImageHandle,
  IN     EFI_HANDLE             DeviceHandle OPTIONAL
  );

/**
  Frees nonexistent I/O, reserved I/O, or I/O resources from the global coherency
  domain of the processor.

  @param  BaseAddress            Base address of the segment.
  @param  Length                 Length of the segment.

  @retval EFI_SUCCESS            Space successfully freed.

**/
EFI_STATUS
EFIAPI
CoreFreeIoSpace (
  IN EFI_PHYSICAL_ADDRESS  BaseAddress,
  IN UINT64                Length
  );

/**
  Removes reserved I/O or I/O resources from the global coherency domain of the
  processor.

  @param  BaseAddress            Base address of the segment.
  @param  Length                 Length of the segment.

  @retval EFI_SUCCESS            Successfully removed a segment of IO space.

**/
EFI_STATUS
EFIAPI
CoreRemoveIoSpace (
  IN EFI_PHYSICAL_ADDRESS  BaseAddress,
  IN UINT64                Length
  );

/**
  Retrieves the descriptor for an I/O region containing a specified address.

  @param  BaseAddress            Specified start address
  @param  Descriptor             Specified length

  @retval EFI_INVALID_PARAMETER  Descriptor is NULL.
  @retval EFI_SUCCESS            Successfully get the IO space descriptor.

**/
EFI_STATUS
EFIAPI
CoreGetIoSpaceDescriptor (
  IN  EFI_PHYSICAL_ADDRESS         BaseAddress,
  OUT EFI_GCD_IO_SPACE_DESCRIPTOR  *Descriptor
  );

/**
  Returns a map of the I/O resources in the global coherency domain of the processor.

  @param  NumberOfDescriptors    Number of descriptors.
  @param  IoSpaceMap             Descriptor array

  @retval EFI_INVALID_PARAMETER  Invalid parameter
  @retval EFI_OUT_OF_RESOURCES   No enough buffer to allocate
  @retval EFI_SUCCESS            Successfully get IO space map.

**/
EFI_STATUS
EFIAPI
CoreGetIoSpaceMap (
  OUT UINTN                        *NumberOfDescriptors,
  OUT EFI_GCD_IO_SPACE_DESCRIPTOR  **IoSpaceMap
  );

/**
  This is the main Dispatcher for DXE and it exits when there are no more
  drivers to run. Drain the mScheduledQueue and load and start a PE
  image for each driver. Search the mDiscoveredList to see if any driver can
  be placed on the mScheduledQueue. If no drivers are placed on the
  mScheduledQueue exit the function. On exit it is assumed the Bds()
  will be called, and when the Bds() exits the Dispatcher will be called
  again.

  @retval EFI_ALREADY_STARTED   The DXE Dispatcher is already running
  @retval EFI_NOT_FOUND         No DXE Drivers were dispatched
  @retval EFI_SUCCESS           One or more DXE Drivers were dispatched

**/
EFI_STATUS
EFIAPI
CoreDispatcher (
  VOID
  );

/**
  Check every driver and locate a matching one. If the driver is found, the Unrequested
  state flag is cleared.

  @param  FirmwareVolumeHandle  The handle of the Firmware Volume that contains
                                the firmware  file specified by DriverName.
  @param  DriverName            The Driver name to put in the Dependent state.

  @retval EFI_SUCCESS           The DriverName was found and it's SOR bit was
                                cleared
  @retval EFI_NOT_FOUND         The DriverName does not exist or it's SOR bit was
                                not set.

**/
EFI_STATUS
EFIAPI
CoreSchedule (
  IN  EFI_HANDLE  FirmwareVolumeHandle,
  IN  EFI_GUID    *DriverName
  );

/**
  Convert a driver from the Untrused back to the Scheduled state.

  @param  FirmwareVolumeHandle  The handle of the Firmware Volume that contains
                                the firmware  file specified by DriverName.
  @param  DriverName            The Driver name to put in the Scheduled state

  @retval EFI_SUCCESS           The file was found in the untrusted state, and it
                                was promoted  to the trusted state.
  @retval EFI_NOT_FOUND         The file was not found in the untrusted state.

**/
EFI_STATUS
EFIAPI
CoreTrust (
  IN  EFI_HANDLE  FirmwareVolumeHandle,
  IN  EFI_GUID    *DriverName
  );

/**
  This routine is the driver initialization entry point.  It initializes the
  libraries, and registers two notification functions.  These notification
  functions are responsible for building the FV stack dynamically.

  @param  ImageHandle           The image handle.
  @param  SystemTable           The system table.

  @retval EFI_SUCCESS           Function successfully returned.

**/
EFI_STATUS
EFIAPI
FwVolDriverInit (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  );

/**
  Entry point of the section extraction code. Initializes an instance of the
  section extraction interface and installs it on a new handle.

  @param  ImageHandle   A handle for the image that is initializing this driver
  @param  SystemTable   A pointer to the EFI system table

  @retval EFI_SUCCESS           Driver initialized successfully
  @retval EFI_OUT_OF_RESOURCES  Could not allocate needed resources

**/
EFI_STATUS
EFIAPI
InitializeSectionExtraction (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  );

/**
  This DXE service routine is used to process a firmware volume. In
  particular, it can be called by BDS to process a single firmware
  volume found in a capsule.

  @param  FvHeader               pointer to a firmware volume header
  @param  Size                   the size of the buffer pointed to by FvHeader
  @param  FVProtocolHandle       the handle on which a firmware volume protocol
                                 was produced for the firmware volume passed in.

  @retval EFI_OUT_OF_RESOURCES   if an FVB could not be produced due to lack of
                                 system resources
  @retval EFI_VOLUME_CORRUPTED   if the volume was corrupted
  @retval EFI_SUCCESS            a firmware volume protocol was produced for the
                                 firmware volume

**/
EFI_STATUS
EFIAPI
CoreProcessFirmwareVolume (
  IN VOID         *FvHeader,
  IN UINTN        Size,
  OUT EFI_HANDLE  *FVProtocolHandle
  );

//
// Functions used during debug buils
//

/**
  Displays Architectural protocols that were not loaded and are required for DXE
  core to function.  Only used in Debug Builds.

**/
VOID
CoreDisplayMissingArchProtocols (
  VOID
  );

/**
  Traverse the discovered list for any drivers that were discovered but not loaded
  because the dependency experessions evaluated to false.

**/
VOID
CoreDisplayDiscoveredNotDispatched (
  VOID
  );

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
  );

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
  );

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
  );

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
  );

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
  );

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
  );

/**
  Decompresses a compressed source buffer.

  The Decompress() function extracts decompressed data to its original form.
  This protocol is designed so that the decompression algorithm can be
  implemented without using any memory services. As a result, the Decompress()
  Function is not allowed to call AllocatePool() or AllocatePages() in its
  implementation. It is the caller's responsibility to allocate and free the
  Destination and Scratch buffers.
  If the compressed source data specified by Source and SourceSize is
  sucessfully decompressed into Destination, then EFI_SUCCESS is returned. If
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
  );

/**
  SEP member function.  This function creates and returns a new section stream
  handle to represent the new section stream.

  @param  SectionStreamLength    Size in bytes of the section stream.
  @param  SectionStream          Buffer containing the new section stream.
  @param  SectionStreamHandle    A pointer to a caller allocated UINTN that on
                                 output contains the new section stream handle.

  @retval EFI_SUCCESS            The section stream is created successfully.
  @retval EFI_OUT_OF_RESOURCES   memory allocation failed.
  @retval EFI_INVALID_PARAMETER  Section stream does not end concident with end
                                 of last section.

**/
EFI_STATUS
EFIAPI
OpenSectionStream (
  IN     UINTN  SectionStreamLength,
  IN     VOID   *SectionStream,
  OUT UINTN     *SectionStreamHandle
  );

/**
  SEP member function.  Retrieves requested section from section stream.

  @param  SectionStreamHandle   The section stream from which to extract the
                                requested section.
  @param  SectionType           A pointer to the type of section to search for.
  @param  SectionDefinitionGuid If the section type is EFI_SECTION_GUID_DEFINED,
                                then SectionDefinitionGuid indicates which of
                                these types of sections to search for.
  @param  SectionInstance       Indicates which instance of the requested
                                section to return.
  @param  Buffer                Double indirection to buffer.  If *Buffer is
                                non-null on input, then the buffer is caller
                                allocated.  If Buffer is NULL, then the buffer
                                is callee allocated.  In either case, the
                                required buffer size is returned in *BufferSize.
  @param  BufferSize            On input, indicates the size of *Buffer if
                                *Buffer is non-null on input.  On output,
                                indicates the required size (allocated size if
                                callee allocated) of *Buffer.
  @param  AuthenticationStatus  A pointer to a caller-allocated UINT32 that
                                indicates the authentication status of the
                                output buffer. If the input section's
                                GuidedSectionHeader.Attributes field
                                has the EFI_GUIDED_SECTION_AUTH_STATUS_VALID
                                bit as clear, AuthenticationStatus must return
                                zero. Both local bits (19:16) and aggregate
                                bits (3:0) in AuthenticationStatus are returned
                                by ExtractSection(). These bits reflect the
                                status of the extraction operation. The bit
                                pattern in both regions must be the same, as
                                the local and aggregate authentication statuses
                                have equivalent meaning at this level. If the
                                function returns anything other than
                                EFI_SUCCESS, the value of *AuthenticationStatus
                                is undefined.
  @param  IsFfs3Fv              Indicates the FV format.

  @retval EFI_SUCCESS           Section was retrieved successfully
  @retval EFI_PROTOCOL_ERROR    A GUID defined section was encountered in the
                                section stream with its
                                EFI_GUIDED_SECTION_PROCESSING_REQUIRED bit set,
                                but there was no corresponding GUIDed Section
                                Extraction Protocol in the handle database.
                                *Buffer is unmodified.
  @retval EFI_NOT_FOUND         An error was encountered when parsing the
                                SectionStream.  This indicates the SectionStream
                                is not correctly formatted.
  @retval EFI_NOT_FOUND         The requested section does not exist.
  @retval EFI_OUT_OF_RESOURCES  The system has insufficient resources to process
                                the request.
  @retval EFI_INVALID_PARAMETER The SectionStreamHandle does not exist.
  @retval EFI_WARN_TOO_SMALL    The size of the caller allocated input buffer is
                                insufficient to contain the requested section.
                                The input buffer is filled and section contents
                                are truncated.

**/
EFI_STATUS
EFIAPI
GetSection (
  IN UINTN             SectionStreamHandle,
  IN EFI_SECTION_TYPE  *SectionType,
  IN EFI_GUID          *SectionDefinitionGuid,
  IN UINTN             SectionInstance,
  IN VOID              **Buffer,
  IN OUT UINTN         *BufferSize,
  OUT UINT32           *AuthenticationStatus,
  IN BOOLEAN           IsFfs3Fv
  );

/**
  SEP member function.  Deletes an existing section stream

  @param  StreamHandleToClose    Indicates the stream to close
  @param  FreeStreamBuffer       TRUE - Need to free stream buffer;
                                 FALSE - No need to free stream buffer.

  @retval EFI_SUCCESS            The section stream is closed sucessfully.
  @retval EFI_OUT_OF_RESOURCES   Memory allocation failed.
  @retval EFI_INVALID_PARAMETER  Section stream does not end concident with end
                                 of last section.

**/
EFI_STATUS
EFIAPI
CloseSectionStream (
  IN  UINTN    StreamHandleToClose,
  IN  BOOLEAN  FreeStreamBuffer
  );

/**
  Creates and initializes the DebugImageInfo Table.  Also creates the configuration
  table and registers it into the system table.

  Note:
    This function allocates memory, frees it, and then allocates memory at an
    address within the initial allocation. Since this function is called early
    in DXE core initialization (before drivers are dispatched), this should not
    be a problem.

**/
VOID
CoreInitializeDebugImageInfoTable (
  VOID
  );

/**
  Update the CRC32 in the Debug Table.
  Since the CRC32 service is made available by the Runtime driver, we have to
  wait for the Runtime Driver to be installed before the CRC32 can be computed.
  This function is called elsewhere by the core when the runtime architectural
  protocol is produced.

**/
VOID
CoreUpdateDebugTableCrc32 (
  VOID
  );

/**
  Adds a new DebugImageInfo structure to the DebugImageInfo Table.  Re-Allocates
  the table if it's not large enough to accomidate another entry.

  @param  ImageInfoType  type of debug image information
  @param  LoadedImage    pointer to the loaded image protocol for the image being
                         loaded
  @param  ImageHandle    image handle for the image being loaded

**/
VOID
CoreNewDebugImageInfoEntry (
  IN  UINT32                     ImageInfoType,
  IN  EFI_LOADED_IMAGE_PROTOCOL  *LoadedImage,
  IN  EFI_HANDLE                 ImageHandle
  );

/**
  Removes and frees an entry from the DebugImageInfo Table.

  @param  ImageHandle    image handle for the image being unloaded

**/
VOID
CoreRemoveDebugImageInfoEntry (
  EFI_HANDLE  ImageHandle
  );

/**
  This routine consumes FV hobs and produces instances of FW_VOL_BLOCK_PROTOCOL as appropriate.

  @param  ImageHandle            The image handle.
  @param  SystemTable            The system table.

  @retval EFI_SUCCESS            Successfully initialized firmware volume block
                                 driver.

**/
EFI_STATUS
EFIAPI
FwVolBlockDriverInit (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  );

/**

  Get FVB authentication status

  @param FvbProtocol    FVB protocol.

  @return Authentication status.

**/
UINT32
GetFvbAuthenticationStatus (
  IN EFI_FIRMWARE_VOLUME_BLOCK_PROTOCOL  *FvbProtocol
  );

/**
  This routine produces a firmware volume block protocol on a given
  buffer.

  @param  BaseAddress            base address of the firmware volume image
  @param  Length                 length of the firmware volume image
  @param  ParentHandle           handle of parent firmware volume, if this image
                                 came from an FV image file and section in another firmware
                                 volume (ala capsules)
  @param  AuthenticationStatus   Authentication status inherited, if this image
                                 came from an FV image file and section in another firmware volume.
  @param  FvProtocol             Firmware volume block protocol produced.

  @retval EFI_VOLUME_CORRUPTED   Volume corrupted.
  @retval EFI_OUT_OF_RESOURCES   No enough buffer to be allocated.
  @retval EFI_SUCCESS            Successfully produced a FVB protocol on given
                                 buffer.

**/
EFI_STATUS
ProduceFVBProtocolOnBuffer (
  IN EFI_PHYSICAL_ADDRESS  BaseAddress,
  IN UINT64                Length,
  IN EFI_HANDLE            ParentHandle,
  IN UINT32                AuthenticationStatus,
  OUT EFI_HANDLE           *FvProtocol  OPTIONAL
  );

/**
  Raising to the task priority level of the mutual exclusion
  lock, and then acquires ownership of the lock.

  @param  Lock               The lock to acquire

  @return Lock owned

**/
VOID
CoreAcquireLock (
  IN EFI_LOCK  *Lock
  );

/**
  Initialize a basic mutual exclusion lock.   Each lock
  provides mutual exclusion access at it's task priority
  level.  Since there is no-premption (at any TPL) or
  multiprocessor support, acquiring the lock only consists
  of raising to the locks TPL.

  @param  Lock               The EFI_LOCK structure to initialize

  @retval EFI_SUCCESS        Lock Owned.
  @retval EFI_ACCESS_DENIED  Reentrant Lock Acquisition, Lock not Owned.

**/
EFI_STATUS
CoreAcquireLockOrFail (
  IN EFI_LOCK  *Lock
  );

/**
  Releases ownership of the mutual exclusion lock, and
  restores the previous task priority level.

  @param  Lock               The lock to release

  @return Lock unowned

**/
VOID
CoreReleaseLock (
  IN EFI_LOCK  *Lock
  );

/**
  Read data from Firmware Block by FVB protocol Read.
  The data may cross the multi block ranges.

  @param  Fvb                   The FW_VOL_BLOCK_PROTOCOL instance from which to read data.
  @param  StartLba              Pointer to StartLba.
                                On input, the start logical block index from which to read.
                                On output,the end logical block index after reading.
  @param  Offset                Pointer to Offset
                                On input, offset into the block at which to begin reading.
                                On output, offset into the end block after reading.
  @param  DataSize              Size of data to be read.
  @param  Data                  Pointer to Buffer that the data will be read into.

  @retval EFI_SUCCESS           Successfully read data from firmware block.
  @retval others
**/
EFI_STATUS
ReadFvbData (
  IN     EFI_FIRMWARE_VOLUME_BLOCK_PROTOCOL  *Fvb,
  IN OUT EFI_LBA                             *StartLba,
  IN OUT UINTN                               *Offset,
  IN     UINTN                               DataSize,
  OUT    UINT8                               *Data
  );

/**
  Given the supplied FW_VOL_BLOCK_PROTOCOL, allocate a buffer for output and
  copy the real length volume header into it.

  @param  Fvb                   The FW_VOL_BLOCK_PROTOCOL instance from which to
                                read the volume header
  @param  FwVolHeader           Pointer to pointer to allocated buffer in which
                                the volume header is returned.

  @retval EFI_OUT_OF_RESOURCES  No enough buffer could be allocated.
  @retval EFI_SUCCESS           Successfully read volume header to the allocated
                                buffer.
  @retval EFI_INVALID_PARAMETER The FV Header signature is not as expected or
                                the file system could not be understood.

**/
EFI_STATUS
GetFwVolHeader (
  IN     EFI_FIRMWARE_VOLUME_BLOCK_PROTOCOL  *Fvb,
  OUT    EFI_FIRMWARE_VOLUME_HEADER          **FwVolHeader
  );

/**
  Verify checksum of the firmware volume header.

  @param  FvHeader       Points to the firmware volume header to be checked

  @retval TRUE           Checksum verification passed
  @retval FALSE          Checksum verification failed

**/
BOOLEAN
VerifyFvHeaderChecksum (
  IN EFI_FIRMWARE_VOLUME_HEADER  *FvHeader
  );

/**
  Initialize memory profile.

  @param HobStart   The start address of the HOB.

**/
VOID
MemoryProfileInit (
  IN VOID  *HobStart
  );

/**
  Install memory profile protocol.

**/
VOID
MemoryProfileInstallProtocol (
  VOID
  );

/**
  Register image to memory profile.

  @param DriverEntry    Image info.
  @param FileType       Image file type.

  @return EFI_SUCCESS           Register successfully.
  @return EFI_UNSUPPORTED       Memory profile unsupported,
                                or memory profile for the image is not required.
  @return EFI_OUT_OF_RESOURCES  No enough resource for this register.

**/
EFI_STATUS
RegisterMemoryProfileImage (
  IN LOADED_IMAGE_PRIVATE_DATA  *DriverEntry,
  IN EFI_FV_FILETYPE            FileType
  );

/**
  Unregister image from memory profile.

  @param DriverEntry    Image info.

  @return EFI_SUCCESS           Unregister successfully.
  @return EFI_UNSUPPORTED       Memory profile unsupported,
                                or memory profile for the image is not required.
  @return EFI_NOT_FOUND         The image is not found.

**/
EFI_STATUS
UnregisterMemoryProfileImage (
  IN LOADED_IMAGE_PRIVATE_DATA  *DriverEntry
  );

/**
  Update memory profile information.

  @param CallerAddress  Address of caller who call Allocate or Free.
  @param Action         This Allocate or Free action.
  @param MemoryType     Memory type.
                        EfiMaxMemoryType means the MemoryType is unknown.
  @param Size           Buffer size.
  @param Buffer         Buffer address.
  @param ActionString   String for memory profile action.
                        Only needed for user defined allocate action.

  @return EFI_SUCCESS           Memory profile is updated.
  @return EFI_UNSUPPORTED       Memory profile is unsupported,
                                or memory profile for the image is not required,
                                or memory profile for the memory type is not required.
  @return EFI_ACCESS_DENIED     It is during memory profile data getting.
  @return EFI_ABORTED           Memory profile recording is not enabled.
  @return EFI_OUT_OF_RESOURCES  No enough resource to update memory profile for allocate action.
  @return EFI_NOT_FOUND         No matched allocate info found for free action.

**/
EFI_STATUS
EFIAPI
CoreUpdateProfile (
  IN EFI_PHYSICAL_ADDRESS   CallerAddress,
  IN MEMORY_PROFILE_ACTION  Action,
  IN EFI_MEMORY_TYPE        MemoryType,
  IN UINTN                  Size,       // Valid for AllocatePages/FreePages/AllocatePool
  IN VOID                   *Buffer,
  IN CHAR8                  *ActionString OPTIONAL
  );

/**
  Internal function.  Converts a memory range to use new attributes.

  @param  Start                  The first address of the range Must be page
                                 aligned
  @param  NumberOfPages          The number of pages to convert
  @param  NewAttributes          The new attributes value for the range.

**/
VOID
CoreUpdateMemoryAttributes (
  IN EFI_PHYSICAL_ADDRESS  Start,
  IN UINT64                NumberOfPages,
  IN UINT64                NewAttributes
  );

/**
  Initialize MemoryAttrubutesTable support.
**/
VOID
EFIAPI
CoreInitializeMemoryAttributesTable (
  VOID
  );

/**
  Initialize Memory Protection support.
**/
VOID
EFIAPI
CoreInitializeMemoryProtection (
  VOID
  );

/**
  Install MemoryAttributesTable on memory allocation.

  @param[in] MemoryType EFI memory type.
**/
VOID
InstallMemoryAttributesTableOnMemoryAllocation (
  IN EFI_MEMORY_TYPE  MemoryType
  );

/**
  Insert image record.

  @param  RuntimeImage    Runtime image information
**/
VOID
InsertImageRecord (
  IN EFI_RUNTIME_IMAGE_ENTRY  *RuntimeImage
  );

/**
  Remove Image record.

  @param  RuntimeImage    Runtime image information
**/
VOID
RemoveImageRecord (
  IN EFI_RUNTIME_IMAGE_ENTRY  *RuntimeImage
  );

/**
  Protect UEFI image.

  @param[in]  LoadedImage              The loaded image protocol
  @param[in]  LoadedImageDevicePath    The loaded image device path protocol
**/
VOID
ProtectUefiImage (
  IN EFI_LOADED_IMAGE_PROTOCOL  *LoadedImage,
  IN EFI_DEVICE_PATH_PROTOCOL   *LoadedImageDevicePath
  );

/**
  Unprotect UEFI image.

  @param[in]  LoadedImage              The loaded image protocol
  @param[in]  LoadedImageDevicePath    The loaded image device path protocol
**/
VOID
UnprotectUefiImage (
  IN EFI_LOADED_IMAGE_PROTOCOL  *LoadedImage,
  IN EFI_DEVICE_PATH_PROTOCOL   *LoadedImageDevicePath
  );

/**
  ExitBootServices Callback function for memory protection.
**/
VOID
MemoryProtectionExitBootServicesCallback (
  VOID
  );

/**
  Manage memory permission attributes on a memory range, according to the
  configured DXE memory protection policy.

  @param  OldType           The old memory type of the range
  @param  NewType           The new memory type of the range
  @param  Memory            The base address of the range
  @param  Length            The size of the range (in bytes)

  @return EFI_SUCCESS       If the the CPU arch protocol is not installed yet
  @return EFI_SUCCESS       If no DXE memory protection policy has been configured
  @return EFI_SUCCESS       If OldType and NewType use the same permission attributes
  @return other             Return value of gCpu->SetMemoryAttributes()

**/
EFI_STATUS
EFIAPI
ApplyMemoryProtectionPolicy (
  IN  EFI_MEMORY_TYPE       OldType,
  IN  EFI_MEMORY_TYPE       NewType,
  IN  EFI_PHYSICAL_ADDRESS  Memory,
  IN  UINT64                Length
  );

/**
  Merge continous memory map entries whose have same attributes.

  @param  MemoryMap       A pointer to the buffer in which firmware places
                          the current memory map.
  @param  MemoryMapSize   A pointer to the size, in bytes, of the
                          MemoryMap buffer. On input, this is the size of
                          the current memory map.  On output,
                          it is the size of new memory map after merge.
  @param  DescriptorSize  Size, in bytes, of an individual EFI_MEMORY_DESCRIPTOR.
**/
VOID
MergeMemoryMap (
  IN OUT EFI_MEMORY_DESCRIPTOR  *MemoryMap,
  IN OUT UINTN                  *MemoryMapSize,
  IN UINTN                      DescriptorSize
  );

/**
  Initializes "handle" support.

  @return Status code.

+**/
EFI_STATUS
CoreInitializeHandleServices (
  VOID
  );

#pragma pack (push,1)
typedef struct {
  UINT16   PchSeries;                               ///< Offset 0       PCH Series
  UINT16   PchGeneration;                           ///< Offset 2       PCH Generation
  UINT16   PchStepping;                             ///< Offset 4       PCH Stepping
  UINT32   RpAddress[24];                           ///< Offset 6       Root Port address 1
                                                    ///< Offset 10      Root Port address 2
                                                    ///< Offset 14      Root Port address 3
                                                    ///< Offset 18      Root Port address 4
                                                    ///< Offset 22      Root Port address 5
                                                    ///< Offset 26      Root Port address 6
                                                    ///< Offset 30      Root Port address 7
                                                    ///< Offset 34      Root Port address 8
                                                    ///< Offset 38      Root Port address 9
                                                    ///< Offset 42      Root Port address 10
                                                    ///< Offset 46      Root Port address 11
                                                    ///< Offset 50      Root Port address 12
                                                    ///< Offset 54      Root Port address 13
                                                    ///< Offset 58      Root Port address 14
                                                    ///< Offset 62      Root Port address 15
                                                    ///< Offset 66      Root Port address 16
                                                    ///< Offset 70      Root Port address 17
                                                    ///< Offset 74      Root Port address 18
                                                    ///< Offset 78      Root Port address 19
                                                    ///< Offset 82      Root Port address 20
                                                    ///< Offset 86      Root Port address 21
                                                    ///< Offset 90      Root Port address 22
                                                    ///< Offset 94      Root Port address 23
                                                    ///< Offset 98      Root Port address 24
  UINT64   NHLA;                                    ///< Offset 102     HD-Audio NHLT ACPI address
  UINT32   NHLL;                                    ///< Offset 110     HD-Audio NHLT ACPI length
  UINT32   ADFM;                                    ///< Offset 114     HD-Audio DSP Feature Mask
  UINT8    SWQ0;                                    ///< Offset 118     HD-Audio SoundWire Link #1 quirk mask
  UINT8    SWQ1;                                    ///< Offset 119     HD-Audio SoundWire Link #2 quirk mask
  UINT8    SWQ2;                                    ///< Offset 120     HD-Audio SoundWire Link #3 quirk mask
  UINT8    SWQ3;                                    ///< Offset 121     HD-Audio SoundWire Link #4 quirk mask
  UINT32   DSPM;                                    ///< Offset 122     HD-Audio DSP Stolen Memory Base Address
  UINT32   SBRG;                                    ///< Offset 126     SBREG_BAR
  UINT8    GEI0;                                    ///< Offset 130     GPIO GroupIndex mapped to GPE_DW0
  UINT8    GEI1;                                    ///< Offset 131     GPIO GroupIndex mapped to GPE_DW1
  UINT8    GEI2;                                    ///< Offset 132     GPIO GroupIndex mapped to GPE_DW2
  UINT8    GED0;                                    ///< Offset 133     GPIO DW part of group mapped to GPE_DW0
  UINT8    GED1;                                    ///< Offset 134     GPIO DW part of group mapped to GPE_DW1
  UINT8    GED2;                                    ///< Offset 135     GPIO DW part of group mapped to GPE_DW2
  UINT16   PcieLtrMaxSnoopLatency[24];              ///< Offset 136     PCIE LTR max snoop Latency 1
                                                    ///< Offset 138     PCIE LTR max snoop Latency 2
                                                    ///< Offset 140     PCIE LTR max snoop Latency 3
                                                    ///< Offset 142     PCIE LTR max snoop Latency 4
                                                    ///< Offset 144     PCIE LTR max snoop Latency 5
                                                    ///< Offset 146     PCIE LTR max snoop Latency 6
                                                    ///< Offset 148     PCIE LTR max snoop Latency 7
                                                    ///< Offset 150     PCIE LTR max snoop Latency 8
                                                    ///< Offset 152     PCIE LTR max snoop Latency 9
                                                    ///< Offset 154     PCIE LTR max snoop Latency 10
                                                    ///< Offset 156     PCIE LTR max snoop Latency 11
                                                    ///< Offset 158     PCIE LTR max snoop Latency 12
                                                    ///< Offset 160     PCIE LTR max snoop Latency 13
                                                    ///< Offset 162     PCIE LTR max snoop Latency 14
                                                    ///< Offset 164     PCIE LTR max snoop Latency 15
                                                    ///< Offset 166     PCIE LTR max snoop Latency 16
                                                    ///< Offset 168     PCIE LTR max snoop Latency 17
                                                    ///< Offset 170     PCIE LTR max snoop Latency 18
                                                    ///< Offset 172     PCIE LTR max snoop Latency 19
                                                    ///< Offset 174     PCIE LTR max snoop Latency 20
                                                    ///< Offset 176     PCIE LTR max snoop Latency 21
                                                    ///< Offset 178     PCIE LTR max snoop Latency 22
                                                    ///< Offset 180     PCIE LTR max snoop Latency 23
                                                    ///< Offset 182     PCIE LTR max snoop Latency 24
  UINT16   PcieLtrMaxNoSnoopLatency[24];            ///< Offset 184     PCIE LTR max no snoop Latency 1
                                                    ///< Offset 186     PCIE LTR max no snoop Latency 2
                                                    ///< Offset 188     PCIE LTR max no snoop Latency 3
                                                    ///< Offset 190     PCIE LTR max no snoop Latency 4
                                                    ///< Offset 192     PCIE LTR max no snoop Latency 5
                                                    ///< Offset 194     PCIE LTR max no snoop Latency 6
                                                    ///< Offset 196     PCIE LTR max no snoop Latency 7
                                                    ///< Offset 198     PCIE LTR max no snoop Latency 8
                                                    ///< Offset 200     PCIE LTR max no snoop Latency 9
                                                    ///< Offset 202     PCIE LTR max no snoop Latency 10
                                                    ///< Offset 204     PCIE LTR max no snoop Latency 11
                                                    ///< Offset 206     PCIE LTR max no snoop Latency 12
                                                    ///< Offset 208     PCIE LTR max no snoop Latency 13
                                                    ///< Offset 210     PCIE LTR max no snoop Latency 14
                                                    ///< Offset 212     PCIE LTR max no snoop Latency 15
                                                    ///< Offset 214     PCIE LTR max no snoop Latency 16
                                                    ///< Offset 216     PCIE LTR max no snoop Latency 17
                                                    ///< Offset 218     PCIE LTR max no snoop Latency 18
                                                    ///< Offset 220     PCIE LTR max no snoop Latency 19
                                                    ///< Offset 222     PCIE LTR max no snoop Latency 20
                                                    ///< Offset 224     PCIE LTR max no snoop Latency 21
                                                    ///< Offset 226     PCIE LTR max no snoop Latency 22
                                                    ///< Offset 228     PCIE LTR max no snoop Latency 23
                                                    ///< Offset 230     PCIE LTR max no snoop Latency 24
  UINT8    XHPC;                                    ///< Offset 232     Number of HighSpeed ports implemented in XHCI controller
  UINT8    XRPC;                                    ///< Offset 233     Number of USBR ports implemented in XHCI controller
  UINT8    XSPC;                                    ///< Offset 234     Number of SuperSpeed ports implemented in XHCI controller
  UINT8    XSPA;                                    ///< Offset 235     Address of 1st SuperSpeed port
  UINT32   HPTB;                                    ///< Offset 236     HPET base address
  UINT8    HPTE;                                    ///< Offset 240     HPET enable
  //SerialIo block
  UINT8    SMD[12];                                 ///< Offset 241     SerialIo controller 0 mode
                                                    ///< Offset 242     SerialIo controller 1 mode
                                                    ///< Offset 243     SerialIo controller 2 mode
                                                    ///< Offset 244     SerialIo controller 3 mode
                                                    ///< Offset 245     SerialIo controller 4 mode
                                                    ///< Offset 246     SerialIo controller 5 mode
                                                    ///< Offset 247     SerialIo controller 6 mode
                                                    ///< Offset 248     SerialIo controller 7 mode
                                                    ///< Offset 249     SerialIo controller 8 mode
                                                    ///< Offset 250     SerialIo controller 9 mode
                                                    ///< Offset 251     SerialIo controller A mode
                                                    ///< Offset 252     SerialIo controller B mode
  UINT8    SIR[12];                                 ///< Offset 253     SerialIo controller 0 irq number
                                                    ///< Offset 254     SerialIo controller 1 irq number
                                                    ///< Offset 255     SerialIo controller 2 irq number
                                                    ///< Offset 256     SerialIo controller 3 irq number
                                                    ///< Offset 257     SerialIo controller 4 irq number
                                                    ///< Offset 258     SerialIo controller 5 irq number
                                                    ///< Offset 259     SerialIo controller 6 irq number
                                                    ///< Offset 260     SerialIo controller 7 irq number
                                                    ///< Offset 261     SerialIo controller 8 irq number
                                                    ///< Offset 262     SerialIo controller 9 irq number
                                                    ///< Offset 263     SerialIo controller A irq number
                                                    ///< Offset 264     SerialIo controller B irq number
  UINT64   SB0[12];                                 ///< Offset 265     SerialIo controller 0 BAR0
                                                    ///< Offset 273     SerialIo controller 1 BAR0
                                                    ///< Offset 281     SerialIo controller 2 BAR0
                                                    ///< Offset 289     SerialIo controller 3 BAR0
                                                    ///< Offset 297     SerialIo controller 4 BAR0
                                                    ///< Offset 305     SerialIo controller 5 BAR0
                                                    ///< Offset 313     SerialIo controller 6 BAR0
                                                    ///< Offset 321     SerialIo controller 7 BAR0
                                                    ///< Offset 329     SerialIo controller 8 BAR0
                                                    ///< Offset 337     SerialIo controller 9 BAR0
                                                    ///< Offset 345     SerialIo controller A BAR0
                                                    ///< Offset 353     SerialIo controller B BAR0
  UINT64   SB1[12];                                 ///< Offset 361     SerialIo controller 0 BAR1
                                                    ///< Offset 369     SerialIo controller 1 BAR1
                                                    ///< Offset 377     SerialIo controller 2 BAR1
                                                    ///< Offset 385     SerialIo controller 3 BAR1
                                                    ///< Offset 393     SerialIo controller 4 BAR1
                                                    ///< Offset 401     SerialIo controller 5 BAR1
                                                    ///< Offset 409     SerialIo controller 6 BAR1
                                                    ///< Offset 417     SerialIo controller 7 BAR1
                                                    ///< Offset 425     SerialIo controller 8 BAR1
                                                    ///< Offset 433     SerialIo controller 9 BAR1
                                                    ///< Offset 441     SerialIo controller A BAR1
                                                    ///< Offset 449     SerialIo controller B BAR1
  //end of SerialIo block
  UINT8    SGIR;                                    ///< Offset 457     GPIO IRQ
  UINT8    GPHD;                                    ///< Offset 458     Hide GPIO ACPI device
  UINT8    RstPcieStorageInterfaceType[3];          ///< Offset 459     RST PCIe Storage Cycle Router#1 Interface Type
                                                    ///< Offset 460     RST PCIe Storage Cycle Router#2 Interface Type
                                                    ///< Offset 461     RST PCIe Storage Cycle Router#3 Interface Type
  UINT8    RstPcieStoragePmCapPtr[3];               ///< Offset 462     RST PCIe Storage Cycle Router#1 Power Management Capability Pointer
                                                    ///< Offset 463     RST PCIe Storage Cycle Router#2 Power Management Capability Pointer
                                                    ///< Offset 464     RST PCIe Storage Cycle Router#3 Power Management Capability Pointer
  UINT8    RstPcieStoragePcieCapPtr[3];             ///< Offset 465     RST PCIe Storage Cycle Router#1 PCIe Capabilities Pointer
                                                    ///< Offset 466     RST PCIe Storage Cycle Router#2 PCIe Capabilities Pointer
                                                    ///< Offset 467     RST PCIe Storage Cycle Router#3 PCIe Capabilities Pointer
  UINT16   RstPcieStorageL1ssCapPtr[3];             ///< Offset 468     RST PCIe Storage Cycle Router#1 L1SS Capability Pointer
                                                    ///< Offset 470     RST PCIe Storage Cycle Router#2 L1SS Capability Pointer
                                                    ///< Offset 472     RST PCIe Storage Cycle Router#3 L1SS Capability Pointer
  UINT8    RstPcieStorageEpL1ssControl2[3];         ///< Offset 474     RST PCIe Storage Cycle Router#1 Endpoint L1SS Control Data2
                                                    ///< Offset 475     RST PCIe Storage Cycle Router#2 Endpoint L1SS Control Data2
                                                    ///< Offset 476     RST PCIe Storage Cycle Router#3 Endpoint L1SS Control Data2
  UINT32   RstPcieStorageEpL1ssControl1[3];         ///< Offset 477     RST PCIe Storage Cycle Router#1 Endpoint L1SS Control Data1
                                                    ///< Offset 481     RST PCIe Storage Cycle Router#2 Endpoint L1SS Control Data1
                                                    ///< Offset 485     RST PCIe Storage Cycle Router#3 Endpoint L1SS Control Data1
  UINT16   RstPcieStorageLtrCapPtr[3];              ///< Offset 489     RST PCIe Storage Cycle Router#1 LTR Capability Pointer
                                                    ///< Offset 491     RST PCIe Storage Cycle Router#2 LTR Capability Pointer
                                                    ///< Offset 493     RST PCIe Storage Cycle Router#3 LTR Capability Pointer
  UINT32   RstPcieStorageEpLtrData[3];              ///< Offset 495     RST PCIe Storage Cycle Router#1 Endpoint LTR Data
                                                    ///< Offset 499     RST PCIe Storage Cycle Router#2 Endpoint LTR Data
                                                    ///< Offset 503     RST PCIe Storage Cycle Router#3 Endpoint LTR Data
  UINT16   RstPcieStorageEpLctlData16[3];           ///< Offset 507     RST PCIe Storage Cycle Router#1 Endpoint LCTL Data
                                                    ///< Offset 509     RST PCIe Storage Cycle Router#2 Endpoint LCTL Data
                                                    ///< Offset 511     RST PCIe Storage Cycle Router#3 Endpoint LCTL Data
  UINT16   RstPcieStorageEpDctlData16[3];           ///< Offset 513     RST PCIe Storage Cycle Router#1 Endpoint DCTL Data
                                                    ///< Offset 515     RST PCIe Storage Cycle Router#2 Endpoint DCTL Data
                                                    ///< Offset 517     RST PCIe Storage Cycle Router#3 Endpoint DCTL Data
  UINT16   RstPcieStorageEpDctl2Data16[3];          ///< Offset 519     RST PCIe Storage Cycle Router#1 Endpoint DCTL2 Data
                                                    ///< Offset 521     RST PCIe Storage Cycle Router#2 Endpoint DCTL2 Data
                                                    ///< Offset 523     RST PCIe Storage Cycle Router#3 Endpoint DCTL2 Data
  UINT16   RstPcieStorageRpDctl2Data16[3];          ///< Offset 525     RST PCIe Storage Cycle Router#1 RootPort DCTL2 Data
                                                    ///< Offset 527     RST PCIe Storage Cycle Router#2 RootPort DCTL2 Data
                                                    ///< Offset 529     RST PCIe Storage Cycle Router#3 RootPort DCTL2 Data
  UINT32   RstPcieStorageUniqueTableBar[3];         ///< Offset 531     RST PCIe Storage Cycle Router#1 Endpoint unique MSI-X Table BAR
                                                    ///< Offset 535     RST PCIe Storage Cycle Router#2 Endpoint unique MSI-X Table BAR
                                                    ///< Offset 539     RST PCIe Storage Cycle Router#3 Endpoint unique MSI-X Table BAR
  UINT32   RstPcieStorageUniqueTableBarValue[3];    ///< Offset 543     RST PCIe Storage Cycle Router#1 Endpoint unique MSI-X Table BAR value
                                                    ///< Offset 547     RST PCIe Storage Cycle Router#2 Endpoint unique MSI-X Table BAR value
                                                    ///< Offset 551     RST PCIe Storage Cycle Router#3 Endpoint unique MSI-X Table BAR value
  UINT32   RstPcieStorageUniquePbaBar[3];           ///< Offset 555     RST PCIe Storage Cycle Router#1 Endpoint unique MSI-X PBA BAR
                                                    ///< Offset 559     RST PCIe Storage Cycle Router#2 Endpoint unique MSI-X PBA BAR
                                                    ///< Offset 563     RST PCIe Storage Cycle Router#3 Endpoint unique MSI-X PBA BAR
  UINT32   RstPcieStorageUniquePbaBarValue[3];      ///< Offset 567     RST PCIe Storage Cycle Router#1 Endpoint unique MSI-X PBA BAR value
                                                    ///< Offset 571     RST PCIe Storage Cycle Router#2 Endpoint unique MSI-X PBA BAR value
                                                    ///< Offset 575     RST PCIe Storage Cycle Router#3 Endpoint unique MSI-X PBA BAR value
  UINT32   RstPcieStorageRootPortNum[3];            ///< Offset 579     RST PCIe Storage Cycle Router#1 Root Port number
                                                    ///< Offset 583     RST PCIe Storage Cycle Router#2 Root Port number
                                                    ///< Offset 587     RST PCIe Storage Cycle Router#3 Root Port number
  UINT8    EMH4;                                    ///< Offset 591     eMMC HS400 mode enabled
  UINT8    EMDS;                                    ///< Offset 592     eMMC Driver Strength
  UINT8    CpuSku;                                  ///< Offset 593     CPU SKU
  UINT16   IoTrapAddress[4];                        ///< Offset 594
  UINT8    IoTrapStatus[4];                         ///< Offset 602
  UINT16   PMBS;                                    ///< Offset 606     ACPI IO BASE address
  UINT32   PWRM;                                    ///< Offset 608     PWRM MEM BASE address
  // Cnvi specific
  UINT8    CnviMode;                                ///< Offset 612     CNVi mode
  UINT32   RmrrCsmeBaseAddress;                     ///< Offset 613     RMRR CSME Base Address
  //Voltage Margining
  UINT8    SlpS0VmRuntimeControl;                   ///< Offset 617     SLP_S0 Voltage Margining Runtime Control
  UINT8    SlpS0Vm070VSupport;                      ///< Offset 618     SLP_S0 0.70V Voltage Margining Support
  UINT8    SlpS0Vm075VSupport;                      ///< Offset 619     SLP_S0 0.75V Voltage Margining Support
  // PCH Trace Hub
  UINT8    PchTraceHubMode;                         ///< Offset 620     PCH Trace Hub Mode
  // PCH PS_ON support
  UINT8    PsOnEnable;                              ///< Offset 621     PCH PS_ON enable
  UINT32   TempRsvdMemBase;                         ///< Offset 622     Reserved memory base address for Temp MBAR
  //
  // These are for PchApciTablesSelfTest use
  //
  UINT8    LtrEnable[24];                           ///< Offset 626     Latency Tolerance Reporting Enable
                                                    ///< Offset 627     Latency Tolerance Reporting Enable
                                                    ///< Offset 628     Latency Tolerance Reporting Enable
                                                    ///< Offset 629     Latency Tolerance Reporting Enable
                                                    ///< Offset 630     Latency Tolerance Reporting Enable
                                                    ///< Offset 631     Latency Tolerance Reporting Enable
                                                    ///< Offset 632     Latency Tolerance Reporting Enable
                                                    ///< Offset 633     Latency Tolerance Reporting Enable
                                                    ///< Offset 634     Latency Tolerance Reporting Enable
                                                    ///< Offset 635     Latency Tolerance Reporting Enable
                                                    ///< Offset 636     Latency Tolerance Reporting Enable
                                                    ///< Offset 637     Latency Tolerance Reporting Enable
                                                    ///< Offset 638     Latency Tolerance Reporting Enable
                                                    ///< Offset 639     Latency Tolerance Reporting Enable
                                                    ///< Offset 640     Latency Tolerance Reporting Enable
                                                    ///< Offset 641     Latency Tolerance Reporting Enable
                                                    ///< Offset 642     Latency Tolerance Reporting Enable
                                                    ///< Offset 643     Latency Tolerance Reporting Enable
                                                    ///< Offset 644     Latency Tolerance Reporting Enable
                                                    ///< Offset 645     Latency Tolerance Reporting Enable
                                                    ///< Offset 646     Latency Tolerance Reporting Enable
                                                    ///< Offset 647     Latency Tolerance Reporting Enable
                                                    ///< Offset 648     Latency Tolerance Reporting Enable
                                                    ///< Offset 649     Latency Tolerance Reporting Enable
  UINT8    GBES;                                    ///< Offset 650     GbE Support
  UINT8    SataPortPresence;                        ///< Offset 651     Holds information from SATA PCS register about SATA ports which recieved COMINIT from connected devices.
  UINT8    SdPowerEnableActiveHigh;                 ///< Offset 652     SD PWREN# active high indication
  UINT8    EmmcEnabled;                             ///< Offset 653     Set to indicate that eMMC is enabled
  UINT8    SdCardEnabled;                           ///< Offset 654     Set to indicate that SD card is enabled
} PCH_NVS_AREA;

#pragma pack(pop)
typedef struct {
  PCH_NVS_AREA                          *Area;
} PCH_NVS_AREA_PROTOCOL;



#pragma pack (push,1)

///
/// Config Block Header
///
typedef struct _CONFIG_BLOCK_HEADER {
  EFI_HOB_GUID_TYPE GuidHob;                      ///< Offset 0-23  GUID extension HOB header
  UINT8             Revision;                     ///< Offset 24    Revision of this config block
  UINT8             Attributes;                   ///< Offset 25    The main revision for config block
  UINT8             Reserved[2];                  ///< Offset 26-27 Reserved for future use
} CONFIG_BLOCK_HEADER;

///
/// Config Block
///
typedef struct _CONFIG_BLOCK {
  CONFIG_BLOCK_HEADER            Header;          ///< Offset 0-27  Header of config block
  //
  // Config Block Data
  //
} CONFIG_BLOCK;

///
/// Config Block Table Header
///
typedef struct _CONFIG_BLOCK_TABLE_STRUCT {
  CONFIG_BLOCK_HEADER            Header;          ///< Offset 0-27  GUID number for main entry of config block
  UINT8                          Rsvd0[2];        ///< Offset 28-29 Reserved for future use
  UINT16                         NumberOfBlocks;  ///< Offset 30-31 Number of config blocks (N)
  UINT32                         AvailableSize;   ///< Offset 32-35 Current config block table size
///
/// Individual Config Block Structures are added here in memory as part of AddConfigBlock()
///
} CONFIG_BLOCK_TABLE_HEADER;
#pragma pack (pop)
typedef struct {
  CONFIG_BLOCK_TABLE_HEADER      TableHeader;    ///< Offset 0-31
/*
  Individual Config Block Structures are added here in memory as part of AddConfigBlock()
*/
} SA_POLICY_PROTOCOL;

#pragma pack (push,1)

/**
  The protocol allows the platform code to publish a set of configuration information that the
  CPU drivers will use to configure the processor in the DXE phase.
  This Policy Protocol needs to be initialized for CPU configuration.
  @note The Protocol has to be published before processor DXE drivers are dispatched.
**/
typedef struct {
  /**
  This member specifies the revision of the Cpu Policy protocol. This field is used to indicate backward
  compatible changes to the protocol. Any such changes to this protocol will result in an update in the revision number.

  <b>Revision 1</b>:
   - Initial version
  **/
  /**
  Policies to obtain CPU temperature.
   - <b>0: ACPI thermal management uses EC reported temperature values</b>.
   - 1: ACPI thermal management uses DTS SMM mechanism to obtain CPU temperature values.
   - 2: ACPI Thermal Management uses EC reported temperature values and DTS SMM is used to handle Out of Spec condition.
  **/
  UINT32                         EnableDts           : 2;
  UINT32                         RsvdBit             : 30;  ///< Reserved bits, align to multiple 32;

  UINT8                          Revision;                  ///< Current revision of policy.
  UINT8                          ReservedByte[3];           ///< Reserved bytes, align to multiple 8.
} DXE_CPU_POLICY_PROTOCOL;

#pragma pack (pop)
typedef struct _EFI_ACPI_SUPPORT_PROTOCOL EFI_ACPI_SUPPORT_PROTOCOL;
typedef UINT32  EFI_ACPI_TABLE_VERSION;
typedef
EFI_STATUS
(EFIAPI *EFI_ACPI_GET_ACPI_TABLE)(
  IN EFI_ACPI_SUPPORT_PROTOCOL            *This,
  IN INTN                                 Index,
  OUT VOID                                **Table,
  OUT EFI_ACPI_TABLE_VERSION              *Version,
  OUT UINTN                               *Handle
  );
typedef
EFI_STATUS
(EFIAPI *EFI_ACPI_SET_ACPI_TABLE)(
  IN EFI_ACPI_SUPPORT_PROTOCOL            *This,
  IN VOID                                 *Table OPTIONAL,
  IN BOOLEAN                              Checksum,
  IN EFI_ACPI_TABLE_VERSION               Version,
  IN OUT UINTN                            *Handle
  );
typedef
EFI_STATUS
(EFIAPI *EFI_ACPI_PUBLISH_TABLES)(
  IN EFI_ACPI_SUPPORT_PROTOCOL            *This,
  IN EFI_ACPI_TABLE_VERSION               Version
  );
struct _EFI_ACPI_SUPPORT_PROTOCOL {
  ///
  /// Returns a table specified by an index if it exists.
  ///
  EFI_ACPI_GET_ACPI_TABLE GetAcpiTable;

  ///
  /// Adds, removes, or updates ACPI tables.
  ///
  EFI_ACPI_SET_ACPI_TABLE SetAcpiTable;

  ///
  /// Publishes the ACPI tables.
  ///
  EFI_ACPI_PUBLISH_TABLES PublishTables;
};

typedef struct _EFI_POWER_MGMT_INIT_DONE_PROTOCOL {
    UINT32 Reserved;  // Reserved for future use, often unused
} EFI_POWER_MGMT_INIT_DONE_PROTOCOL;

#pragma pack (push,1)
typedef struct {
  //
  // Miscellaneous Dynamic Registers:
  //
  UINT16   OperatingSystem;                         ///< Offset 0       Operating System
  UINT8    SmiFunction;                             ///< Offset 2       SMI Function Call (ASL to SMI via I/O Trap)
  UINT8    SmiParameter0;                           ///< Offset 3       SMIF - Parameter 0
  UINT8    SmiParameter1;                           ///< Offset 4       SMIF - Parameter 1
  UINT8    SciFunction;                             ///< Offset 5       SCI Function Call (SMI to ASL via _L00)
  UINT8    SciParameter0;                           ///< Offset 6       SCIF - Parameter 0
  UINT8    SciParameter1;                           ///< Offset 7       SCIF - Parameter 1
  UINT8    GlobalLock;                              ///< Offset 8       Global Lock Function Call (EC Communication)
  UINT8    LockParameter0;                          ///< Offset 9       LCKF - Parameter 0
  UINT8    LockParameter1;                          ///< Offset 10      LCKF - Parameter 1
  UINT8    PowerState;                              ///< Offset 11      Power State (AC Mode = 1)
  UINT8    DebugState;                              ///< Offset 12      Debug State
  //
  // Thermal Policy Registers:
  //
  UINT8    EnableThermalKSC;                        ///< Offset 13      Enable Thermal Offset for KSC
  UINT8    Ac1TripPoint;                            ///< Offset 14      Active Trip Point 1
  UINT8    Ac0TripPoint;                            ///< Offset 15      Active Trip Point
  UINT8    PassiveThermalTripPoint;                 ///< Offset 16      Passive Trip Point
  UINT8    PassiveTc1Value;                         ///< Offset 17      Passive Trip Point TC1 Value
  UINT8    PassiveTc2Value;                         ///< Offset 18      Passive Trip Point TC2 Value
  UINT8    PassiveTspValue;                         ///< Offset 19      Passive Trip Point TSP Value
  UINT8    CriticalThermalTripPoint;                ///< Offset 20      Critical Trip Point
  UINT8    EnableDigitalThermalSensor;              ///< Offset 21      Digital Thermal Sensor Enable
  UINT8    BspDigitalThermalSensorTemperature;      ///< Offset 22      Digital Thermal Sensor 1 Reading
  UINT8    ApDigitalThermalSensorTemperature;       ///< Offset 23      Digital Thermal Sensor 2 Reading
  UINT8    DigitalThermalSensorSmiFunction;         ///< Offset 24      DTS SMI Function Call
  //
  // Revision Field:
  //
  UINT8    Revision;                                ///< Offset 25      Revison of GlobalNvsArea
  //
  // CPU Identification Registers:
  //
  UINT8    ApicEnable;                              ///< Offset 26      APIC Enabled by SBIOS (APIC Enabled = 1)
  UINT8    ThreadCount;                             ///< Offset 27      Number of Enabled Threads
  UINT8    CurentPdcState0;                         ///< Offset 28      PDC Settings, Processor 0
  UINT8    CurentPdcState1;                         ///< Offset 29      PDC Settings, Processor 1
  UINT8    MaximumPpcState;                         ///< Offset 30      Maximum PPC state
  UINT32   PpmFlags;                                ///< Offset 31      PPM Flags (Same as CFGD)
  UINT8    C6C7Latency;                             ///< Offset 35      C6/C7 Entry/Exit latency
  //
  // SIO Configuration Registers:
  //
  UINT8    DockedSioPresent;                        ///< Offset 36      National SIO Present
  UINT8    DockComA;                                ///< Offset 37      COM A Port
  UINT8    DockComB;                                ///< Offset 38      COM B Port
  UINT8    DockLpt;                                 ///< Offset 39      LPT Port
  UINT8    DockFdc;                                 ///< Offset 40      FDC Port
  UINT8    OnboardCom;                              ///< Offset 41      SMSC Com Port
  UINT8    OnboardComCir;                           ///< Offset 42      SMSC Com CIR Port
  UINT8    SMSC1007;                                ///< Offset 43      SMSC1007 SIO Present
  UINT8    WPCN381U;                                ///< Offset 44      WPCN381U SIO Present
  UINT8    SMSC1000;                                ///< Offset 45      SMSC1000 SIO Present
  //
  // Extended Mobile Access Values
  //
  UINT8    EmaEnable;                               ///< Offset 46      EMA Enable
  UINT16   EmaPointer;                              ///< Offset 47      EMA Pointer
  UINT16   EmaLength;                               ///< Offset 49      EMA Length
  //
  // MEF Registers:
  //
  UINT8    MefEnable;                               ///< Offset 51      MEF Enable
  //
  // PCIe Dock Status:
  //
  UINT8    PcieDockStatus;                          ///< Offset 52      PCIe Dock Status
  //
  // TPM Registers
  //
  UINT8    MorData;                                 ///< Offset 53      Memory Overwrite Request Data
  UINT8    TcgParamter;                             ///< Offset 54      Used for save the Mor and/or physical presence paramter
  UINT32   PPResponse;                              ///< Offset 55      Physical Presence request operation response
  UINT8    PPRequest;                               ///< Offset 59      Physical Presence request operation
  UINT8    LastPPRequest;                           ///< Offset 60      Last Physical Presence request operation
  //
  // SATA Registers:
  //
  UINT8    IdeMode;                                 ///< Offset 61      IDE Mode (Compatible\Enhanced)
  //
  // Board Id
  //
  UINT8    PlatformId;                              ///< Offset 62      Platform id
  UINT8    BoardType;                               ///< Offset 63      Board Type
  //
  // PCIe Hot Plug
  //
  UINT8    PcieOSCControl;                          ///< Offset 64      PCIE OSC Control
  UINT8    NativePCIESupport;                       ///< Offset 65      Native PCIE Setup Value
  //
  // USB Sideband Deferring Support
  //
  UINT8    HostAlertVector1;                        ///< Offset 66      USB Sideband Deferring GPE Vector (HOST_ALERT#1)
  UINT8    HostAlertVector2;                        ///< Offset 67      USB Sideband Deferring GPE Vector (HOST_ALERT#2)
  //
  // Embedded Controller Availability Flag.
  //
  UINT8    EcAvailable;                             ///< Offset 68      Embedded Controller Availability Flag.
  //
  // Global Variables
  //
  UINT8    DisplaySupportFlag;                      ///< Offset 69      _DOS Display Support Flag.
  UINT8    InterruptModeFlag;                       ///< Offset 70      Global IOAPIC/8259 Interrupt Mode Flag.
  UINT8    CoolingTypeFlag;                         ///< Offset 71      Global Cooling Type Flag.
  UINT8    L01Counter;                              ///< Offset 72      Global L01 Counter.
  UINT8    VirtualFan0Status;                       ///< Offset 73      Virtual Fan0 Status.
  UINT8    VirtualFan1Status;                       ///< Offset 74      Virtual Fan1 Status.
  UINT8    VirtualFan2Status;                       ///< Offset 75      Virtual Fan2 Status.
  UINT8    VirtualFan3Status;                       ///< Offset 76      Virtual Fan3 Status.
  UINT8    VirtualFan4Status;                       ///< Offset 77      Virtual Fan4 Status.
  UINT8    VirtualFan5Status;                       ///< Offset 78      Virtual Fan5 Status.
  UINT8    VirtualFan6Status;                       ///< Offset 79      Virtual Fan6 Status.
  UINT8    VirtualFan7Status;                       ///< Offset 80      Virtual Fan7 Status.
  UINT8    VirtualFan8Status;                       ///< Offset 81      Virtual Fan8 Status.
  UINT8    VirtualFan9Status;                       ///< Offset 82      Virtual Fan9 Status.
  //
  // Thermal
  //
  UINT8    ActiveThermalTripPointSA;                ///< Offset 83      Active Trip Point for MCH
  UINT8    PassiveThermalTripPointSA;               ///< Offset 84      Passive Trip Point for MCH
  UINT32   PlatformCpuId;                           ///< Offset 85      CPUID Feature Information [EAX]
  UINT32   TBARB;                                   ///< Offset 89      Reserved for Thermal Base Low Address for BIOS
  UINT32   TBARBH;                                  ///< Offset 93      Reserved for Thermal Base High Address for BIOS
  UINT8    TsOnDimmEnabled;                         ///< Offset 97      TS-on-DIMM is chosen in SETUP and present on the DIMM
  //
  // Board info
  //
  UINT8    PlatformFlavor;                          ///< Offset 98      Platform Flavor
  UINT8    BoardRev;                                ///< Offset 99      Board Rev
  //
  // Package temperature
  //
  UINT8    PackageDTSTemperature;                   ///< Offset 100     Package Temperature
  UINT8    IsPackageTempMSRAvailable;               ///< Offset 101     Package Temperature MSR available
  UINT8    PeciAccessMethod;                        ///< Offset 102     Peci Access Method
  UINT8    Ac0FanSpeed;                             ///< Offset 103     _AC0 Fan Speed
  UINT8    Ac1FanSpeed;                             ///< Offset 104     _AC1 Fan Speed
  UINT8    Ap2DigitalThermalSensorTemperature;      ///< Offset 105     Digital Thermal Sensor 3 Reading
  UINT8    Ap3DigitalThermalSensorTemperature;      ///< Offset 106     Digital Thermal Sensor 4 Reading
  //
  // XTU 3.0 Specification
  //
  UINT32   XTUBaseAddress;                          ///< Offset 107     XTU Continous structure Base Address
  UINT32   XTUSize;                                 ///< Offset 111     XMP Size
  UINT32   XMPBaseAddress;                          ///< Offset 115     XMP Base Address
  UINT8    DDRReferenceFreq;                        ///< Offset 119     DDR Reference Frequency
  UINT8    Rtd3Support;                             ///< Offset 120     Runtime D3 support.
  UINT8    Rtd3P0dl;                                ///< Offset 121     User selctable Delay for Device D0 transition.
  UINT8    Rtd3P3dl;                                ///< Offset 122     User selctable Delay for Device D3 transition.
  //
  // DPTF Devices and trip points
  //
  UINT8    EnableDptf;                              ///< Offset 123     EnableDptf
  UINT16   EnableDCFG;                              ///< Offset 124     EnableDCFG
  UINT8    EnableSaDevice;                          ///< Offset 126     EnableSaDevice
  UINT8    CriticalThermalTripPointSA;              ///< Offset 127     CriticalThermalTripPointSa
  UINT8    HotThermalTripPointSA;                   ///< Offset 128     HotThermalTripPointSa
  UINT8    ThermalSamplingPeriodSA;                 ///< Offset 129     ThermalSamplingPeriodSA
  //
  // DPTF Policies
  //
  UINT8    EnableCtdpPolicy;                        ///< Offset 130     EnableCtdpPolicy
  //
  // DPPM Devices and trip points
  //
  UINT8    EnableFan1Device;                        ///< Offset 131     EnableFan1Device
  UINT8    EnableAmbientDevice;                     ///< Offset 132     EnableAmbientDevice
  UINT8    ActiveThermalTripPointAmbient;           ///< Offset 133     ActiveThermalTripPointAmbient
  UINT8    PassiveThermalTripPointAmbient;          ///< Offset 134     PassiveThermalTripPointAmbient
  UINT8    CriticalThermalTripPointAmbient;         ///< Offset 135     CriticalThermalTripPointAmbient
  UINT8    HotThermalTripPointAmbient;              ///< Offset 136     HotThermalTripPointAmbient
  UINT8    EnableSkinDevice;                        ///< Offset 137     EnableSkinDevice
  UINT8    ActiveThermalTripPointSkin;              ///< Offset 138     ActiveThermalTripPointSkin
  UINT8    PassiveThermalTripPointSkin;             ///< Offset 139     PassiveThermalTripPointSkin
  UINT8    CriticalThermalTripPointSkin;            ///< Offset 140     CriticalThermalTripPointSkin
  UINT8    HotThermalTripPointSkin;                 ///< Offset 141     HotThermalTripPointSkin
  UINT8    EnableExhaustFanDevice;                  ///< Offset 142     EnableExhaustFanDevice
  UINT8    ActiveThermalTripPointExhaustFan;        ///< Offset 143     ActiveThermalTripPointExhaustFan
  UINT8    PassiveThermalTripPointExhaustFan;       ///< Offset 144     PassiveThermalTripPointExhaustFan
  UINT8    CriticalThermalTripPointExhaustFan;      ///< Offset 145     CriticalThermalTripPointExhaustFan
  UINT8    HotThermalTripPointExhaustFan;           ///< Offset 146     HotThermalTripPointExhaustFan
  UINT8    EnableVRDevice;                          ///< Offset 147     EnableVRDevice
  UINT8    ActiveThermalTripPointVR;                ///< Offset 148     ActiveThermalTripPointVR
  UINT8    PassiveThermalTripPointVR;               ///< Offset 149     PassiveThermalTripPointVR
  UINT8    CriticalThermalTripPointVR;              ///< Offset 150     CriticalThermalTripPointVR
  UINT8    HotThermalTripPointVR;                   ///< Offset 151     HotThermalTripPointVR
  //
  // DPPM Policies
  //
  UINT8    EnableActivePolicy;                      ///< Offset 152     EnableActivePolicy
  UINT8    EnablePassivePolicy;                     ///< Offset 153     EnablePassivePolicy
  UINT8    EnableCriticalPolicy;                    ///< Offset 154     EnableCriticalPolicy
  UINT8    EnablePIDPolicy;                         ///< Offset 155     EnablePIDPolicy
  UINT8    TrtRevision;                             ///< Offset 156     TrtRevision
  //
  // CLPO (Current Logical Processor Off lining Setting)
  //
  UINT8    LPOEnable;                               ///< Offset 157     LPOEnable
  UINT8    LPOStartPState;                          ///< Offset 158     LPOStartPState
  UINT8    LPOStepSize;                             ///< Offset 159     LPOStepSize
  UINT8    LPOPowerControlSetting;                  ///< Offset 160     LPOPowerControlSetting
  UINT8    LPOPerformanceControlSetting;            ///< Offset 161     LPOPerformanceControlSetting
  //
  // Miscellaneous DPTF
  //
  UINT32   PpccStepSize;                            ///< Offset 162     PPCC Step Size
  UINT8    EnableDisplayParticipant;                ///< Offset 166     EnableDisplayParticipant
  //
  // BIOS Guard
  //
  UINT64   BiosGuardMemAddress;                     ///< Offset 167     BIOS Guard Memory Address for Tool Interface
  UINT8    BiosGuardMemSize;                        ///< Offset 175     BIOS Guard Memory Size for Tool Interface
  UINT16   BiosGuardIoTrapAddress;                  ///< Offset 176     BIOS Guard IoTrap Address for Tool Interface
  //
  // Never Sleep Technology
  //
  UINT8    IrmtCfg;                                 ///< Offset 178     Irmt Configuration
  //
  // Comms Hub
  //
  UINT8    CommsHubEnable;                          ///< Offset 179     Comms Hub Enable/Disable
  UINT8    LowPowerS0Idle;                          ///< Offset 180     Low Power S0 Idle Enable
  //
  // BIOS only version of Config TDP
  //
  UINT8    ConfigTdpBios;                           ///< Offset 181     enable/disable BIOS only version of Config TDP
  UINT8    DockSmi;                                 ///< Offset 182     Dock SMI number
  //
  // LPC SIO configuration
  //
  UINT16   LpcSioPort1;                             ///< Offset 183     SIO config port 1
  UINT16   LpcSioPort2;                             ///< Offset 185     SIO config port 2
  UINT16   LpcSioPmeBar;                            ///< Offset 187     SIO PME Base Address
  UINT8    Reserved0[311];                          ///< Offset 189:499
  UINT8    EnableWrlsParticipant;                   ///< Offset 500     EnableWrlsParticipant
  UINT8    ActiveThermalTripPointWrls;              ///< Offset 501     ActiveThermalTripPointWrls
  UINT8    PassiveThermalTripPointWrls;             ///< Offset 502     PassiveThermalTripPointWrls
  UINT8    CriticalThermalTripPointWrls;            ///< Offset 503     CriticalThermalTripPointWrls
  UINT8    HotThermalTripPointWrls;                 ///< Offset 504     HotThermalTripPointWrls
  UINT8    EnablePowerParticipant;                  ///< Offset 505     EnablePowerParticipant
  UINT16   DPTFRsvd0;                               ///< Offset 506     DPTFRsvd0
  UINT16   PowerParticipantPollingRate;             ///< Offset 508     PowerParticipantPollingRate
  UINT8    EnablePowerBossPolicy;                   ///< Offset 510     EnablePowerBossPolicy
  UINT8    EnableVSPolicy;                          ///< Offset 511     EnableVSPolicy
  UINT8    EnableRFIMPolicy;                        ///< Offset 512     RFI Mitigation
  UINT8    Reserved1[2];                            ///< Offset 513:514
  UINT8    UsbPowerResourceTest;                    ///< Offset 515     RTD3 USB Power Resource config
  UINT8    Rtd3I2C0SensorHub;                       ///< Offset 516     RTD3 support for I2C0 SH
  UINT8    VirtualGpioButtonSxBitmask;              ///< Offset 517     Virtual GPIO button Notify Sleep State Change
  UINT8    IuerButtonEnable;                        ///< Offset 518     IUER Button Enable
  UINT8    IuerConvertibleEnable;                   ///< Offset 519     IUER Convertible Enable
  UINT8    IuerDockEnable;                          ///< Offset 520     IUER Dock Enable
  UINT8    CSNotifyEC;                              ///< Offset 521     EC Notification of Low Power S0 Idle State
  UINT16   Rtd3AudioDelay;                          ///< Offset 522     RTD3 Audio Codec device delay
  UINT16   Rtd3SensorHub;                           ///< Offset 524     RTD3 SensorHub delay time after applying power to device
  UINT16   Rtd3TouchPanelDelay;                     ///< Offset 526     RTD3 TouchPanel delay time after applying power to device
  UINT16   Rtd3TouchPadDelay;                       ///< Offset 528     RTD3 TouchPad delay time after applying power to device
  UINT16   VRRampUpDelay;                           ///< Offset 530     VR Ramp up delay
  UINT8    PstateCapping;                           ///< Offset 532     P-state Capping
  UINT16   Rtd3I2C0ControllerPS0Delay;              ///< Offset 533     Delay in _PS0 after powering up I2C0 Controller
  UINT16   Rtd3I2C1ControllerPS0Delay;              ///< Offset 535     Delay in _PS0 after powering up I2C1 Controller
  UINT16   Rtd3Config0;                             ///< Offset 537     RTD3 Config Setting0(BIT0:ZPODD, BIT1:Reserved, BIT2:PCIe NVMe, Bit4:SKL SDS SIP I2C Touch, BIT6:Card Reader, BIT7:WWAN)
  UINT16   Rtd3Config1;                             ///< Offset 539     RTD3 Config Setting1(BIT0:Sata Port0, BIT1:Sata Port1, BIT2:Sata Port2, BIT3:Sata Port3)
  UINT8    CSDebugLightEC;                          ///< Offset 541     EC Debug Light (CAPS LOCK) for when in Low Power S0 Idle State
  UINT8    Ps2MouseEnable;                          ///< Offset 542     Ps2 Mouse Enable
  UINT8    Ps2KbMsEnable;                           ///< Offset 543     Ps2 Keyboard and Mouse Enable
  UINT8    DiscreteWifiRtd3ColdSupport;             ///< Offset 544     Enable RTD3 Cold Support for Wifi
  UINT8    DiscreteWigigRtd3ColdSupport;            ///< Offset 545     Enable RTD3 Cold Support for Wigig
  UINT8    DiscreteWwanRtd3ColdSupport;             ///< Offset 546     Enable RTD3 Cold Support for WWAN
  UINT16   SSH0;                                    ///< Offset 547     SSCN-HIGH for I2C0
  UINT16   SSL0;                                    ///< Offset 549     SSCN-LOW  for I2C0
  UINT16   SSD0;                                    ///< Offset 551     SSCN-HOLD for I2C0
  UINT16   FMH0;                                    ///< Offset 553     FMCN-HIGH for I2C0
  UINT16   FML0;                                    ///< Offset 555     FMCN-LOW  for I2C0
  UINT16   FMD0;                                    ///< Offset 557     FMCN-HOLD for I2C0
  UINT16   FPH0;                                    ///< Offset 559     FPCN-HIGH for I2C0
  UINT16   FPL0;                                    ///< Offset 561     FPCN-LOW  for I2C0
  UINT16   FPD0;                                    ///< Offset 563     FPCN-HOLD for I2C0
  UINT16   HSH0;                                    ///< Offset 565     HSCN-HIGH for I2C0
  UINT16   HSL0;                                    ///< Offset 567     HSCN-LOW  for I2C0
  UINT16   HSD0;                                    ///< Offset 569     HSCN-HOLD for I2C0
  UINT8    Reserved2[2];                            ///< Offset 571:572
  UINT16   SSH1;                                    ///< Offset 573     SSCN-HIGH for I2C1
  UINT16   SSL1;                                    ///< Offset 575     SSCN-LOW  for I2C1
  UINT16   SSD1;                                    ///< Offset 577     SSCN-HOLD for I2C1
  UINT16   FMH1;                                    ///< Offset 579     FMCN-HIGH for I2C1
  UINT16   FML1;                                    ///< Offset 581     FMCN-LOW  for I2C1
  UINT16   FMD1;                                    ///< Offset 583     FMCN-HOLD for I2C1
  UINT16   FPH1;                                    ///< Offset 585     FPCN-HIGH for I2C1
  UINT16   FPL1;                                    ///< Offset 587     FPCN-LOW  for I2C1
  UINT16   FPD1;                                    ///< Offset 589     FPCN-HOLD for I2C1
  UINT16   HSH1;                                    ///< Offset 591     HSCN-HIGH for I2C1
  UINT16   HSL1;                                    ///< Offset 593     HSCN-LOW  for I2C1
  UINT16   HSD1;                                    ///< Offset 595     HSCN-HOLD for I2C1
  UINT8    Reserved3[1];                            ///< Offset 597:597
  UINT16   SSH2;                                    ///< Offset 598     SSCN-HIGH for I2C2
  UINT16   SSL2;                                    ///< Offset 600     SSCN-LOW  for I2C2
  UINT16   SSD2;                                    ///< Offset 602     SSCN-HOLD for I2C2
  UINT16   FMH2;                                    ///< Offset 604     FMCN-HIGH for I2C2
  UINT16   FML2;                                    ///< Offset 606     FMCN-LOW  for I2C2
  UINT16   FMD2;                                    ///< Offset 608     FMCN-HOLD for I2C2
  UINT16   FPH2;                                    ///< Offset 610     FPCN-HIGH for I2C2
  UINT16   FPL2;                                    ///< Offset 612     FPCN-LOW  for I2C2
  UINT16   FPD2;                                    ///< Offset 614     FPCN-HOLD for I2C2
  UINT16   HSH2;                                    ///< Offset 616     HSCN-HIGH for I2C2
  UINT16   HSL2;                                    ///< Offset 618     HSCN-LOW  for I2C2
  UINT16   HSD2;                                    ///< Offset 620     HSCN-HOLD for I2C2
  UINT8    Reserved4[1];                            ///< Offset 622:622
  UINT16   SSH3;                                    ///< Offset 623     SSCN-HIGH for I2C3
  UINT16   SSL3;                                    ///< Offset 625     SSCN-LOW  for I2C3
  UINT16   SSD3;                                    ///< Offset 627     SSCN-HOLD for I2C3
  UINT16   FMH3;                                    ///< Offset 629     FMCN-HIGH for I2C3
  UINT16   FML3;                                    ///< Offset 631     FMCN-LOW  for I2C3
  UINT16   FMD3;                                    ///< Offset 633     FMCN-HOLD for I2C3
  UINT16   FPH3;                                    ///< Offset 635     FPCN-HIGH for I2C3
  UINT16   FPL3;                                    ///< Offset 637     FPCN-LOW  for I2C3
  UINT16   FPD3;                                    ///< Offset 639     FPCN-HOLD for I2C3
  UINT16   HSH3;                                    ///< Offset 641     HSCN-HIGH for I2C3
  UINT16   HSL3;                                    ///< Offset 643     HSCN-LOW  for I2C3
  UINT16   HSD3;                                    ///< Offset 645     HSCN-HOLD for I2C3
  UINT8    Reserved5[1];                            ///< Offset 647:647
  UINT16   SSH4;                                    ///< Offset 648     SSCN-HIGH for I2C4
  UINT16   SSL4;                                    ///< Offset 650     SSCN-LOW  for I2C4
  UINT16   SSD4;                                    ///< Offset 652     SSCN-HOLD for I2C4
  UINT16   FMH4;                                    ///< Offset 654     FMCN-HIGH for I2C4
  UINT16   FML4;                                    ///< Offset 656     FMCN-LOW  for I2C4
  UINT16   FMD4;                                    ///< Offset 658     FMCN-HOLD for I2C4
  UINT16   FPH4;                                    ///< Offset 660     FPCN-HIGH for I2C4
  UINT16   FPL4;                                    ///< Offset 662     FPCN-LOW  for I2C4
  UINT16   FPD4;                                    ///< Offset 664     FPCN-HOLD for I2C4
  UINT16   HSH4;                                    ///< Offset 666     HSCN-HIGH for I2C4
  UINT16   HSL4;                                    ///< Offset 668     HSCN-LOW  for I2C4
  UINT16   HSD4;                                    ///< Offset 670     HSCN-HOLD for I2C4
  UINT8    Reserved6[1];                            ///< Offset 672:672
  UINT16   SSH5;                                    ///< Offset 673     SSCN-HIGH for I2C5
  UINT16   SSL5;                                    ///< Offset 675     SSCN-LOW  for I2C5
  UINT16   SSD5;                                    ///< Offset 677     SSCN-HOLD for I2C5
  UINT16   FMH5;                                    ///< Offset 679     FMCN-HIGH for I2C5
  UINT16   FML5;                                    ///< Offset 681     FMCN-LOW  for I2C5
  UINT16   FMD5;                                    ///< Offset 683     FMCN-HOLD for I2C5
  UINT16   FPH5;                                    ///< Offset 685     FPCN-HIGH for I2C5
  UINT16   FPL5;                                    ///< Offset 687     FPCN-LOW  for I2C5
  UINT16   FPD5;                                    ///< Offset 689     FPCN-HOLD for I2C5
  UINT16   HSH5;                                    ///< Offset 691     HSCN-HIGH for I2C5
  UINT16   HSL5;                                    ///< Offset 693     HSCN-LOW  for I2C5
  UINT16   HSD5;                                    ///< Offset 695     HSCN-HOLD for I2C5
  UINT8    Reserved7[1];                            ///< Offset 697:697
  UINT16   M0C0;                                    ///< Offset 698     M0D3 for I2C0
  UINT16   M1C0;                                    ///< Offset 700     M1D3 for I2C0
  UINT16   M0C1;                                    ///< Offset 702     M0D3 for I2C1
  UINT16   M1C1;                                    ///< Offset 704     M1D3 for I2C1
  UINT16   M0C2;                                    ///< Offset 706     M0D3 for I2C2
  UINT16   M1C2;                                    ///< Offset 708     M1D3 for I2C2
  UINT16   M0C3;                                    ///< Offset 710     M0D3 for I2C3
  UINT16   M1C3;                                    ///< Offset 712     M1D3 for I2C3
  UINT16   M0C4;                                    ///< Offset 714     M0D3 for I2C4
  UINT16   M1C4;                                    ///< Offset 716     M1D3 for I2C4
  UINT16   M0C5;                                    ///< Offset 718     M0D3 for I2C5
  UINT16   M1C5;                                    ///< Offset 720     M1D3 for I2C5
  UINT16   M0C6;                                    ///< Offset 722     M0D3 for SPI0
  UINT16   M1C6;                                    ///< Offset 724     M1D3 for SPI0
  UINT16   M0C7;                                    ///< Offset 726     M0D3 for SPI1
  UINT16   M1C7;                                    ///< Offset 728     M1D3 for SPI1
  UINT16   M0C8;                                    ///< Offset 730     M0D3 for SPI2
  UINT16   M1C8;                                    ///< Offset 732     M1D3 for SPI2
  UINT8    Reserved8[1];                            ///< Offset 734:734
  UINT16   M0C9;                                    ///< Offset 735     M0D3 for UART0
  UINT16   M1C9;                                    ///< Offset 737     M1D3 for UART0
  UINT16   M0CA;                                    ///< Offset 739     M0D3 for UART1
  UINT16   M1CA;                                    ///< Offset 741     M1D3 for UART1
  UINT16   M0CB;                                    ///< Offset 743     M0D3 for UART2
  UINT16   M1CB;                                    ///< Offset 745     M1D3 for UART2
  UINT8    Reserved9[1];                            ///< Offset 747:747
  //
  // Driver Mode
  //
  UINT32   GpioIrqRoute;                            ///< Offset 748     GPIO IRQ
  UINT8    DriverModeTouchPanel;                    ///< Offset 752     PIRQS 34,50(GPIO)
  UINT8    DriverModeTouchPad;                      ///< Offset 753     PIRQX 39,55(GPIO)
  UINT8    DriverModeSensorHub;                     ///< Offset 754     PIRQM 28,14(GPIO)
  UINT8    SensorStandby;                           ///< Offset 755     Sensor Standby mode
  UINT8    PL1LimitCS;                              ///< Offset 756     set PL1 limit when entering CS
  UINT16   PL1LimitCSValue;                         ///< Offset 757     PL1 limit value
  UINT8    EnableWwanTempSensorDevice;              ///< Offset 759     EnableWwanTempSensorDevice
  UINT8    EnableCpuVrTempSensorDevice;             ///< Offset 760     EnableCpuVrTempSensorDevice
  UINT8    EnableSsdTempSensorDevice;               ///< Offset 761     EnableSsdTempSensorDevice
  UINT8    EnableInletFanTempSensorDevice;          ///< Offset 762     EnableInletFanTempSensorDevice
  UINT8    ActiveThermalTripPointInletFan;          ///< Offset 763     ActiveThermalTripPointInletFan
  UINT8    PassiveThermalTripPointInletFan;         ///< Offset 764     PassiveThermalTripPointInletFan
  UINT8    CriticalThermalTripPointInletFan;        ///< Offset 765     CriticalThermalTripPointInletFan
  UINT8    HotThermalTripPointInletFan;             ///< Offset 766     HotThermalTripPointInletFan
  UINT8    UsbSensorHub;                            ///< Offset 767     Sensor Hub Type - (0)None, (1)USB, (2)I2C Intel, (3)I2C STM
  UINT8    BCV4;                                    ///< Offset 768     Broadcom's Bluetooth adapter's revision
  UINT8    WTV0;                                    ///< Offset 769     I2C0/WITT devices version
  UINT8    WTV1;                                    ///< Offset 770     I2C1/WITT devices version
  UINT8    AtmelPanelFwUpdate;                      ///< Offset 771     Atmel panel FW update Enable/Disable
  UINT8    Reserved10[6];                           ///< Offset 772:777
  UINT32   LowPowerS0IdleConstraint;                ///< Offset 778     PEP Constraints
  // Bit[1:0] - Storage (0:None, 1:Storage Controller, 2:Raid)
  // Bit[2]   - En/Dis UART0
  // Bit[3]   - En/Dis UART1
  // Bit[4]   - Unused
  // Bit[5]   - En/Dis I2C0
  // Bit[6]   - En/Dis I2C1
  // Bit[7]   - En/Dis XHCI
  // Bit[8]   - En/Dis HD Audio (includes ADSP)
  // Bit[9]   - En/Dis Gfx
  // Bit[10]  - En/Dis CPU
  // Bit[11]  - En/Dis EMMC
  // Bit[12]  - En/Dis SDXC
  // Bit[13]  - En/Dis I2C2
  // Bit[14]  - En/Dis I2C3
  // Bit[15]  - En/Dis I2C4
  // Bit[16]  - En/Dis I2C5
  // Bit[17]  - En/Dis UART2
  // Bit[18]  - En/Dis SPI0
  // Bit[19]  - En/Dis SPI1
  // Bit[20]  - [CNL] En/Dis SPI2
  // Bit[21]  - En/Dis IPU0
  // Bit[22]  - En/Dis CSME
  // Bit[23]  - En/Dis LAN(GBE)
  UINT16   VRStaggeringDelay;                       ///< Offset 782     VR Staggering delay
  UINT8    TenSecondPowerButtonEnable;              ///< Offset 784     10sec Power button support
  // Bit0: 10 sec P-button Enable/Disable
  // Bit1: Internal Flag
  // Bit2: Rotation Lock flag, 0:unlock, 1:lock
  // Bit3: Slate/Laptop Mode Flag, 0: Slate, 1: Laptop
  // Bit4: Undock / Dock Flag, 0: Undock, 1: Dock
  // Bit5: VBDL Flag. 0: VBDL is not called, 1: VBDL is called, Virtual Button Driver is loaded.
  // Bit6: Reserved for future use.
  // Bit7: EC 10sec PB Override state for S3/S4 wake up.
  //
  // Generation Id(Tock/Tick)
  //
  UINT8    GenerationId;                            ///< Offset 785     Generation Id(0=Shark bay, 1=Crescent Bay)
  //
  // DPTF
  //
  UINT8    EnableWWANParticipant;                   ///< Offset 786     EnableWWANParticipant
  UINT8    ActiveThermalTripPointWWAN;              ///< Offset 787     ActiveThermalTripPointWWAN
  UINT8    PassiveThermalTripPointWWAN;             ///< Offset 788     PassiveThermalTripPointWWAN
  UINT8    CriticalThermalTripPointWWAN;            ///< Offset 789     CriticalThermalTripPointWWAN
  UINT8    HotThermalTripPointWWAN;                 ///< Offset 790     HotThermalTripPointWWAN
  UINT8    Reserved11[16];                          ///< Offset 791:806
  UINT16   MinPowerLimit0;                          ///< Offset 807     Minimum Power Limit 0 for DPTF use via PPCC Object
  UINT8    EnableChargerParticipant;                ///< Offset 809     EnableChargerParticipant
  UINT8    CriticalThermalTripPointSaS3;            ///< Offset 810     CriticalThermalTripPointSaS3
  UINT8    CriticalThermalTripPointAmbientS3;       ///< Offset 811     CriticalThermalTripPointAmbientS3
  UINT8    CriticalThermalTripPointSkinS3;          ///< Offset 812     CriticalThermalTripPointSkinS3
  UINT8    CriticalThermalTripPointExhaustFanS3;    ///< Offset 813     CriticalThermalTripPointExhaustFanS3
  UINT8    CriticalThermalTripPointVrS3;            ///< Offset 814     CriticalThermalTripPointVRS3
  UINT8    CriticalThermalTripPointWrlsS3;          ///< Offset 815     CriticalThermalTripPointWrlsS3
  UINT8    CriticalThermalTripPointInletFanS3;      ///< Offset 816     CriticalThermalTripPointInletFanS3
  UINT8    CriticalThermalTripPointWwanS3;          ///< Offset 817     CriticalThermalTripPointWWANS3
  UINT8    CriticalThermalTripPointWGigS3;          ///< Offset 818     CriticalThermalTripPointWGigS3
  UINT8    SataPortState;                           ///< Offset 819     SATA port state, Bit0 - Port0, Bit1 - Port1, Bit2 - Port2, Bit3 - Port3
  //
  // DPTF
  //
  UINT8    Enable2DCameraParticipant;               ///< Offset 820     Enable2DCameraParticipant
  UINT8    EnableBatteryParticipant;                ///< Offset 821     EnableBatteryParticipant
  UINT8    EcLowPowerMode;                          ///< Offset 822     EC Low Power Mode: 1 - Enabled, 0 - Disabled
  UINT8    SensorSamplingPeriodSen1;                ///< Offset 823     SensorSamplingPeriodSen1
  UINT8    SensorSamplingPeriodSen2;                ///< Offset 824     SensorSamplingPeriodSen2
  UINT8    SensorSamplingPeriodSen3;                ///< Offset 825     SensorSamplingPeriodSen3
  UINT8    SensorSamplingPeriodSen4;                ///< Offset 826     SensorSamplingPeriodSen4
  UINT8    SensorSamplingPeriodSen5;                ///< Offset 827     SensorSamplingPeriodSen5
  UINT8    ThermalSamplingPeriodTMEM;               ///< Offset 828     ThermalSamplingPeriodTMEM @deprecated. Memory Participant is not POR for DPTF
  UINT8    EnableStorageParticipantST1;             ///< Offset 829     EnableStorageParticipantST1
  UINT8    ActiveThermalTripPointST1;               ///< Offset 830     ActiveThermalTripPointST1
  UINT8    PassiveThermalTripPointST1;              ///< Offset 831     PassiveThermalTripPointST1
  UINT8    CriticalThermalTripPointST1;             ///< Offset 832     CriticalThermalTripPointST1
  UINT8    CriticalThermalTripPointS3ST1;           ///< Offset 833     CriticalThermalTripPointS3ST1
  UINT8    HotThermalTripPointST1;                  ///< Offset 834     HotThermalTripPointST1
  UINT8    EnableStorageParticipantST2;             ///< Offset 835     EnableStorageParticipantST2
  UINT8    ActiveThermalTripPointST2;               ///< Offset 836     ActiveThermalTripPointST2
  UINT8    PassiveThermalTripPointST2;              ///< Offset 837     PassiveThermalTripPointST2
  UINT8    CriticalThermalTripPointST2;             ///< Offset 838     CriticalThermalTripPointST2
  UINT8    CriticalThermalTripPointS3ST2;           ///< Offset 839     CriticalThermalTripPointS3ST2
  UINT8    HotThermalTripPointST2;                  ///< Offset 840     HotThermalTripPointST2
  UINT8    EnableVS1Participant;                    ///< Offset 841     EnableVS1Participant
  UINT8    ActiveThermalTripPointVS1;               ///< Offset 842     ActiveThermalTripPointVS1
  UINT8    PassiveThermalTripPointVS1;              ///< Offset 843     PassiveThermalTripPointVS1
  UINT8    CriticalThermalTripPointVS1;             ///< Offset 844     CriticalThermalTripPointVS1
  UINT8    CriticalThermalTripPointVS1S3;           ///< Offset 845     CriticalThermalTripPointVS1S3
  UINT8    HotThermalTripPointVS1;                  ///< Offset 846     HotThermalTripPointVS1
  UINT8    EnableVS2Participant;                    ///< Offset 847     EnableVS2Participant
  UINT8    ActiveThermalTripPointVS2;               ///< Offset 848     ActiveThermalTripPointVS2
  UINT8    PassiveThermalTripPointVS2;              ///< Offset 849     PassiveThermalTripPointVS2
  UINT8    CriticalThermalTripPointVS2;             ///< Offset 850     CriticalThermalTripPointVS2
  UINT8    CriticalThermalTripPointVS2S3;           ///< Offset 851     CriticalThermalTripPointVS2S3
  UINT8    HotThermalTripPointVS2;                  ///< Offset 852     HotThermalTripPointVS2
  UINT8    EnableSen1Participant;                   ///< Offset 853     EnableSen1Participant
  UINT8    ActiveThermalTripPointSen1;              ///< Offset 854     ActiveThermalTripPointSen1
  UINT8    PassiveThermalTripPointSen1;             ///< Offset 855     PassiveThermalTripPointSen1
  UINT8    CriticalThermalTripPointSen1;            ///< Offset 856     CriticalThermalTripPointSen1
  UINT8    HotThermalTripPointSen1;                 ///< Offset 857     HotThermalTripPointSen1
  UINT8    EnableSen2Participant;                   ///< Offset 858     EnableSen2Participant
  UINT8    ActiveThermalTripPointSen2;              ///< Offset 859     ActiveThermalTripPointSen2
  UINT8    PassiveThermalTripPointSen2;             ///< Offset 860     PassiveThermalTripPointSen2
  UINT8    CriticalThermalTripPointSen2;            ///< Offset 861     CriticalThermalTripPointSen2
  UINT8    HotThermalTripPointSen2;                 ///< Offset 862     HotThermalTripPointSen2
  UINT8    EnableSen3Participant;                   ///< Offset 863     EnableSen3Participant
  UINT8    ActiveThermalTripPointSen3;              ///< Offset 864     ActiveThermalTripPointSen3
  UINT8    PassiveThermalTripPointSen3;             ///< Offset 865     PassiveThermalTripPointSen3
  UINT8    CriticalThermalTripPointSen3;            ///< Offset 866     CriticalThermalTripPointSen3
  UINT8    HotThermalTripPointSen3;                 ///< Offset 867     HotThermalTripPointSen3
  UINT8    EnableSen4Participant;                   ///< Offset 868     EnableSen4Participant
  UINT8    ActiveThermalTripPointSen4;              ///< Offset 869     ActiveThermalTripPointSen4
  UINT8    PassiveThermalTripPointSen4;             ///< Offset 870     PassiveThermalTripPointSen4
  UINT8    CriticalThermalTripPointSen4;            ///< Offset 871     CriticalThermalTripPointSen4
  UINT8    HotThermalTripPointSen4;                 ///< Offset 872     HotThermalTripPointSen4
  UINT8    EnableSen5Participant;                   ///< Offset 873     EnableSen5Participant
  UINT8    ActiveThermalTripPointSen5;              ///< Offset 874     ActiveThermalTripPointSen5
  UINT8    PassiveThermalTripPointSen5;             ///< Offset 875     PassiveThermalTripPointSen5
  UINT8    CriticalThermalTripPointSen5;            ///< Offset 876     CriticalThermalTripPointSen5
  UINT8    HotThermalTripPointSen5;                 ///< Offset 877     HotThermalTripPointSen5
  UINT8    CriticalThermalTripPointSen1S3;          ///< Offset 878     CriticalThermalTripPointSen1S3
  UINT8    CriticalThermalTripPointSen2S3;          ///< Offset 879     CriticalThermalTripPointSen2S3
  UINT8    CriticalThermalTripPointSen3S3;          ///< Offset 880     CriticalThermalTripPointSen3S3
  UINT8    CriticalThermalTripPointSen4S3;          ///< Offset 881     CriticalThermalTripPointSen4S3
  UINT8    CriticalThermalTripPointSen5S3;          ///< Offset 882     CriticalThermalTripPointSen5S3
  UINT8    PowerSharingManagerEnable;               ///< Offset 883     PowerSharingManagerEnable
  UINT8    PsmSplcDomainType1;                      ///< Offset 884     PsmSplcDomainType1
  UINT32   PsmSplcPowerLimit1;                      ///< Offset 885     PsmSplcPowerLimit1
  UINT32   PsmSplcTimeWindow1;                      ///< Offset 889     PsmSplcTimeWindow1
  UINT8    PsmSplcDomainType2;                      ///< Offset 893     PsmSplcDomainType2
  UINT32   PsmSplcPowerLimit2;                      ///< Offset 894     PsmSplcPowerLimit2
  UINT32   PsmSplcTimeWindow2;                      ///< Offset 898     PsmSplcTimeWindow2
  UINT8    PsmDplcDomainType1;                      ///< Offset 902     PsmDplcDomainType1
  UINT8    PsmDplcDomainPreference1;                ///< Offset 903     PsmDplcDomainPreference1
  UINT16   PsmDplcPowerLimitIndex1;                 ///< Offset 904     PsmDplcPowerLimitIndex1
  UINT16   PsmDplcDefaultPowerLimit1;               ///< Offset 906     PsmDplcDefaultPowerLimit1
  UINT32   PsmDplcDefaultTimeWindow1;               ///< Offset 908     PsmDplcDefaultTimeWindow1
  UINT16   PsmDplcMinimumPowerLimit1;               ///< Offset 912     PsmDplcMinimumPowerLimit1
  UINT16   PsmDplcMaximumPowerLimit1;               ///< Offset 914     PsmDplcMaximumPowerLimit1
  UINT16   PsmDplcMaximumTimeWindow1;               ///< Offset 916     PsmDplcMaximumTimeWindow1
  UINT8    PsmDplcDomainType2;                      ///< Offset 918     PsmDplcDomainType2
  UINT8    PsmDplcDomainPreference2;                ///< Offset 919     PsmDplcDomainPreference2
  UINT16   PsmDplcPowerLimitIndex2;                 ///< Offset 920     PsmDplcPowerLimitIndex2
  UINT16   PsmDplcDefaultPowerLimit2;               ///< Offset 922     PsmDplcDefaultPowerLimit2
  UINT32   PsmDplcDefaultTimeWindow2;               ///< Offset 924     PsmDplcDefaultTimeWindow2
  UINT16   PsmDplcMinimumPowerLimit2;               ///< Offset 928     PsmDplcMinimumPowerLimit2
  UINT16   PsmDplcMaximumPowerLimit2;               ///< Offset 930     PsmDplcMaximumPowerLimit2
  UINT16   PsmDplcMaximumTimeWindow2;               ///< Offset 932     PsmDplcMaximumTimeWindow2
  UINT8    WifiEnable;                              ///< Offset 934     WifiEnable
  UINT8    WifiDomainType1;                         ///< Offset 935     WifiDomainType1
  UINT16   WifiPowerLimit1;                         ///< Offset 936     WifiPowerLimit1
  UINT32   WifiTimeWindow1;                         ///< Offset 938     WifiTimeWindow1
  UINT8    WifiDomainType2;                         ///< Offset 942     WifiDomainType2
  UINT16   WifiPowerLimit2;                         ///< Offset 943     WifiPowerLimit2
  UINT32   WifiTimeWindow2;                         ///< Offset 945     WifiTimeWindow2
  UINT8    WifiDomainType3;                         ///< Offset 949     WifiDomainType3
  UINT16   WifiPowerLimit3;                         ///< Offset 950     WifiPowerLimit3
  UINT32   WifiTimeWindow3;                         ///< Offset 952     WifiTimeWindow3
  UINT8    TRxDelay0;                               ///< Offset 956     TRxDelay0
  UINT8    TRxCableLength0;                         ///< Offset 957     TRxCableLength0
  UINT8    TRxDelay1;                               ///< Offset 958     TRxDelay1
  UINT8    TRxCableLength1;                         ///< Offset 959     TRxCableLength1
  UINT8    WrddDomainType1;                         ///< Offset 960     WrddDomainType1
  UINT16   WrddCountryIndentifier1;                 ///< Offset 961     WrddCountryIndentifier1
  UINT8    WrddDomainType2;                         ///< Offset 963     WrddDomainType2
  UINT16   WrddCountryIndentifier2;                 ///< Offset 964     WrddCountryIndentifier2
  UINT8    Reserved12[52];                          ///< Offset 966:1017
  UINT8    EnableAPPolicy;                          ///< Offset 1018    Adaptive Performance Policy
  UINT16   MinPowerLimit1;                          ///< Offset 1019    Minimum Power Limit 1 for DPTF use via PPCC Object
  UINT16   MinPowerLimit2;                          ///< Offset 1021    Minimum Power Limit 2 for DPTF use via PPCC Object
  //
  // Intel Serial(R) IO Sensor Device Selection
  //
  UINT8    SDS0;                                    ///< Offset 1023    SerialIo Devices for controller0
  UINT8    SDS1;                                    ///< Offset 1024    SerialIo Devices for controller1
  UINT8    SDS2;                                    ///< Offset 1025    SerialIo Devices for controller2
  UINT8    SDS3;                                    ///< Offset 1026    SerialIo Devices for controller3
  UINT8    SDS4;                                    ///< Offset 1027    SerialIo Devices for controller4
  UINT8    SDS5;                                    ///< Offset 1028    SerialIo Devices for controller5
  UINT8    SDS6;                                    ///< Offset 1029    SerialIo Devices for controller6
  UINT8    SDS7;                                    ///< Offset 1030    SerialIo Devices for controller7
  UINT8    SDS8;                                    ///< Offset 1031    SerialIo Devices for controller8
  UINT8    SDS9;                                    ///< Offset 1032    SerialIo Devices for controller9
  UINT8    SDSA;                                    ///< Offset 1033    SerialIo Devices for controller10
  UINT8    TPLT;                                    ///< Offset 1034    I2C SerialIo Devices Type of TouchPanel
  UINT8    TPLM;                                    ///< Offset 1035    I2C SerialIo Devices Interrupt Mode for TouchPanel
  UINT8    TPLB;                                    ///< Offset 1036    I2C Custom TouchPanel's BUS Address
  UINT16   TPLH;                                    ///< Offset 1037    I2C Custom TouchPanel's HID Address
  UINT8    TPLS;                                    ///< Offset 1039    I2C Custom TouchPanel's BUS Speed
  UINT8    TPDT;                                    ///< Offset 1040    I2C SerialIo Devices Type of TouchPad
  UINT8    TPDM;                                    ///< Offset 1041    I2C SerialIo Devices Interrupt Mode for TouchPad
  UINT8    TPDB;                                    ///< Offset 1042    I2C Custom TouchPad's BUS Address
  UINT16   TPDH;                                    ///< Offset 1043    I2C Custom TouchPad's HID Address
  UINT8    TPDS;                                    ///< Offset 1045    I2C Custom TouchPad's BUS Speed
  UINT8    FPTT;                                    ///< Offset 1046    SPI SerialIo Devices Type of FingerPrint
  UINT8    FPTM;                                    ///< Offset 1047    SPI SerialIo Devices Interrupt Mode for FingerPrint
  UINT8    WTVX;                                    ///< Offset 1048    WITT test devices' version
  UINT8    WITX;                                    ///< Offset 1049    WITT test devices' connection point
  UINT8    GPTD;                                    ///< Offset 1050    GPIO test devices
  UINT16   GDBT;                                    ///< Offset 1051    GPIO test devices' debounce value,
  UINT8    UTKX;                                    ///< Offset 1053    UTK test devices' connection point
  UINT8    SPTD;                                    ///< Offset 1054    SerialIo additional test devices
  UINT8    DMTX;                                    ///< Offset 1055     DMA Test device enable
  UINT8    Reserved13[10];                          ///< Offset 1056:1065
  UINT32   TableLoadBuffer;                         ///< Offset 1066    Buffer for runtime ACPI Table loading
  UINT8    SDM0;                                    ///< Offset 1070    interrupt mode for controller0 devices
  UINT8    SDM1;                                    ///< Offset 1071    interrupt mode for controller1 devices
  UINT8    SDM2;                                    ///< Offset 1072    interrupt mode for controller2 devices
  UINT8    SDM3;                                    ///< Offset 1073    interrupt mode for controller3 devices
  UINT8    SDM4;                                    ///< Offset 1074    interrupt mode for controller4 devices
  UINT8    SDM5;                                    ///< Offset 1075    interrupt mode for controller5 devices
  UINT8    SDM6;                                    ///< Offset 1076    interrupt mode for controller6 devices
  UINT8    SDM7;                                    ///< Offset 1077    interrupt mode for controller7 devices
  UINT8    SDM8;                                    ///< Offset 1078    interrupt mode for controller8 devices
  UINT8    SDM9;                                    ///< Offset 1079    interrupt mode for controller9 devices
  UINT8    SDMA;                                    ///< Offset 1080    interrupt mode for controller10 devices
  UINT8    SDMB;                                    ///< Offset 1081    interrupt mode for controller11 devices
  UINT8    Reserved14[1];                           ///< Offset 1082:1082
  UINT8    USTP;                                    ///< Offset 1083    use SerialIo timing parameters
  UINT8    Reserved15[41];                          ///< Offset 1084:1124
  UINT32   FingerPrintSleepGpio;                    ///< Offset 1125    Gpio for fingerprint sleep
  UINT32   FingerPrintIrqGpio;                      ///< Offset 1129    Gpio for fingerprint irq
  UINT8    DiscreteGnssModule;                      ///< Offset 1133    GNSS module and its interface, 0=disabled, 1=CG2000 over SerialIo Uart, 2=CG2000 over ISH Uart
  UINT32   DiscreteGnssModuleResetGpio;             ///< Offset 1134    Gpio for GNSS reset
  UINT32   DiscreteBtModuleRfKillGpio;              ///< Offset 1138    Gpio for Bluetooth RfKill
  UINT32   DiscreteBtModuleIrqGpio;                 ///< Offset 1142    Gpio for Bluetooth interrupt
  UINT32   TouchpadIrqGpio;                         ///< Offset 1146    Gpio for touchPaD Interrupt
  UINT32   TouchpanelIrqGpio;                       ///< Offset 1150    Gpio for touchPaneL Interrupt
  UINT8    DiscreteBtUartSupport;                   ///< Offset 1154    Switch to enable BT UART Support
  UINT8    DiscreteGnssSupport;                     ///< Offset 1155    Switch to enable GNSS Support
  //
  // MipiCam specific
  //
  UINT8    MipiCamControlLogic0;                    ///< Offset 1156    
  UINT8    MipiCamControlLogic1;                    ///< Offset 1157    
  UINT8    MipiCamControlLogic2;                    ///< Offset 1158    
  UINT8    MipiCamControlLogic3;                    ///< Offset 1159    
  UINT8    MipiCamLink0Enabled;                     ///< Offset 1160    
  UINT8    MipiCamLink1Enabled;                     ///< Offset 1161    
  UINT8    MipiCamLink2Enabled;                     ///< Offset 1162    
  UINT8    MipiCamLink3Enabled;                     ///< Offset 1163    
  UINT8    MipiCamLanesClkDiv;                      ///< Offset 1164    
  // Control Logic 0 options
  UINT8    MipiCamCtrlLogic0_Version;               ///< Offset 1165    Version of CLDB structure
  UINT8    MipiCamCtrlLogic0_Type;                  ///< Offset 1166    Type
  UINT8    MipiCamCtrlLogic0_CrdVersion;            ///< Offset 1167    Version of CRD
  UINT32   MipiCamCtrlLogic0_InputClock;            ///< Offset 1168    Input Clock
  UINT8    MipiCamCtrlLogic0_GpioPinsEnabled;       ///< Offset 1172    Number of GPIO Pins enabled
  UINT8    MipiCamCtrlLogic0_I2cBus;                ///< Offset 1173    I2C Serial Bus Number
  UINT16   MipiCamCtrlLogic0_I2cAddress;            ///< Offset 1174    I2C Address
  UINT8    MipiCamCtrlLogic0_GpioGroupPadNumber[4]; ///< Offset 1176    GPIO Group Pad Number
  UINT8    MipiCamCtrlLogic0_GpioGroupNumber[4];    ///< Offset 1180    GPIO Group Number
  UINT8    MipiCamCtrlLogic0_GpioFunction[4];       ///< Offset 1184    GPIO Function
  UINT8    MipiCamCtrlLogic0_GpioActiveValue[4];    ///< Offset 1188    GPIO Active Value
  UINT8    MipiCamCtrlLogic0_GpioInitialValue[4];   ///< Offset 1192    GPIO Initial Value
  UINT8    MipiCamCtrlLogic0_Pld;                   ///< Offset 1196    Camera Position
  UINT8    MipiCamCtrlLogic0_Wled1FlashMaxCurrent;  ///< Offset 1197    WLED1 Flash Max Current
  UINT8    MipiCamCtrlLogic0_Wled1TorchMaxCurrent;  ///< Offset 1198    WLED1 Torch Max Current
  UINT8    MipiCamCtrlLogic0_Wled2FlashMaxCurrent;  ///< Offset 1199    WLED2 Flash Max Current
  UINT8    MipiCamCtrlLogic0_Wled2TorchMaxCurrent;  ///< Offset 1200    WLED2 Torch Max Current
  UINT8    MipiCamCtrlLogic0_SubPlatformId;         ///< Offset 1201    Sub Platform Id
  UINT8    MipiCamCtrlLogic0_Wled1Type;             ///< Offset 1202    WLED1 Type
  UINT8    MipiCamCtrlLogic0_Wled2Type;             ///< Offset 1203    WLED2 Type
  UINT8    MipiCamCtrlLogic0_PchClockSource;        ///< Offset 1204    PCH Clock source
  // Control Logic 1 options
  UINT8    MipiCamCtrlLogic1_Version;               ///< Offset 1205    Version of CLDB structure
  UINT8    MipiCamCtrlLogic1_Type;                  ///< Offset 1206    Type
  UINT8    MipiCamCtrlLogic1_CrdVersion;            ///< Offset 1207    Version of CRD
  UINT32   MipiCamCtrlLogic1_InputClock;            ///< Offset 1208    Input Clock
  UINT8    MipiCamCtrlLogic1_GpioPinsEnabled;       ///< Offset 1212    Number of GPIO Pins enabled
  UINT8    MipiCamCtrlLogic1_I2cBus;                ///< Offset 1213    I2C Serial Bus Number
  UINT16   MipiCamCtrlLogic1_I2cAddress;            ///< Offset 1214    I2C Address
  UINT8    MipiCamCtrlLogic1_GpioGroupPadNumber[4]; ///< Offset 1216    GPIO Group Pad Number
  UINT8    MipiCamCtrlLogic1_GpioGroupNumber[4];    ///< Offset 1220    GPIO Group Number
  UINT8    MipiCamCtrlLogic1_GpioFunction[4];       ///< Offset 1224    GPIO Function
  UINT8    MipiCamCtrlLogic1_GpioActiveValue[4];    ///< Offset 1228    GPIO Active Value
  UINT8    MipiCamCtrlLogic1_GpioInitialValue[4];   ///< Offset 1232    GPIO Initial Value
  UINT8    MipiCamCtrlLogic1_Pld;                   ///< Offset 1236    Camera Position
  UINT8    MipiCamCtrlLogic1_Wled1FlashMaxCurrent;  ///< Offset 1237    WLED1 Flash Max Current
  UINT8    MipiCamCtrlLogic1_Wled1TorchMaxCurrent;  ///< Offset 1238    WLED1 Torch Max Current
  UINT8    MipiCamCtrlLogic1_Wled2FlashMaxCurrent;  ///< Offset 1239    WLED2 Flash Max Current
  UINT8    MipiCamCtrlLogic1_Wled2TorchMaxCurrent;  ///< Offset 1240    WLED2 Torch Max Current
  UINT8    MipiCamCtrlLogic1_SubPlatformId;         ///< Offset 1241    Sub Platform Id
  UINT8    MipiCamCtrlLogic1_Wled1Type;             ///< Offset 1242    WLED1 Type
  UINT8    MipiCamCtrlLogic1_Wled2Type;             ///< Offset 1243    WLED2 Type
  UINT8    MipiCamCtrlLogic1_PchClockSource;        ///< Offset 1244    PCH Clock source
  // Control Logic 2 options
  UINT8    MipiCamCtrlLogic2_Version;               ///< Offset 1245    Version of CLDB structure
  UINT8    MipiCamCtrlLogic2_Type;                  ///< Offset 1246    Type
  UINT8    MipiCamCtrlLogic2_CrdVersion;            ///< Offset 1247    Version of CRD
  UINT32   MipiCamCtrlLogic2_InputClock;            ///< Offset 1248    Input Clock
  UINT8    MipiCamCtrlLogic2_GpioPinsEnabled;       ///< Offset 1252    Number of GPIO Pins enabled
  UINT8    MipiCamCtrlLogic2_I2cBus;                ///< Offset 1253    I2C Serial Bus Number
  UINT16   MipiCamCtrlLogic2_I2cAddress;            ///< Offset 1254    I2C Address
  UINT8    MipiCamCtrlLogic2_GpioGroupPadNumber[4]; ///< Offset 1256    GPIO Group Pad Number
  UINT8    MipiCamCtrlLogic2_GpioGroupNumber[4];    ///< Offset 1260    GPIO Group Number
  UINT8    MipiCamCtrlLogic2_GpioFunction[4];       ///< Offset 1264    GPIO Function
  UINT8    MipiCamCtrlLogic2_GpioActiveValue[4];    ///< Offset 1268    GPIO Active Value
  UINT8    MipiCamCtrlLogic2_GpioInitialValue[4];   ///< Offset 1272    GPIO Initial Value
  UINT8    MipiCamCtrlLogic2_Pld;                   ///< Offset 1276    Camera Position
  UINT8    MipiCamCtrlLogic2_Wled1FlashMaxCurrent;  ///< Offset 1277    WLED1 Flash Max Current
  UINT8    MipiCamCtrlLogic2_Wled1TorchMaxCurrent;  ///< Offset 1278    WLED1 Torch Max Current
  UINT8    MipiCamCtrlLogic2_Wled2FlashMaxCurrent;  ///< Offset 1279    WLED2 Flash Max Current
  UINT8    MipiCamCtrlLogic2_Wled2TorchMaxCurrent;  ///< Offset 1280    WLED2 Torch Max Current
  UINT8    MipiCamCtrlLogic2_SubPlatformId;         ///< Offset 1281    Sub Platform Id
  UINT8    MipiCamCtrlLogic2_Wled1Type;             ///< Offset 1282    WLED1 Type
  UINT8    MipiCamCtrlLogic2_Wled2Type;             ///< Offset 1283    WLED2 Type
  UINT8    MipiCamCtrlLogic2_PchClockSource;        ///< Offset 1284    PCH Clock source
  // Control Logic 3 options
  UINT8    MipiCamCtrlLogic3_Version;               ///< Offset 1285    Version of CLDB structure
  UINT8    MipiCamCtrlLogic3_Type;                  ///< Offset 1286    Type
  UINT8    MipiCamCtrlLogic3_CrdVersion;            ///< Offset 1287    Version of CRD
  UINT32   MipiCamCtrlLogic3_InputClock;            ///< Offset 1288    Input Clock
  UINT8    MipiCamCtrlLogic3_GpioPinsEnabled;       ///< Offset 1292    Number of GPIO Pins enabled
  UINT8    MipiCamCtrlLogic3_I2cBus;                ///< Offset 1293    I2C Serial Bus Number
  UINT16   MipiCamCtrlLogic3_I2cAddress;            ///< Offset 1294    I2C Address
  UINT8    MipiCamCtrlLogic3_GpioGroupPadNumber[4]; ///< Offset 1296    GPIO Group Pad Number
  UINT8    MipiCamCtrlLogic3_GpioGroupNumber[4];    ///< Offset 1300    GPIO Group Number
  UINT8    MipiCamCtrlLogic3_GpioFunction[4];       ///< Offset 1304    GPIO Function
  UINT8    MipiCamCtrlLogic3_GpioActiveValue[4];    ///< Offset 1308    GPIO Active Value
  UINT8    MipiCamCtrlLogic3_GpioInitialValue[4];   ///< Offset 1312    GPIO Initial Value
  UINT8    MipiCamCtrlLogic3_Pld;                   ///< Offset 1316    Camera Position
  UINT8    MipiCamCtrlLogic3_Wled1FlashMaxCurrent;  ///< Offset 1317    WLED1 Flash Max Current
  UINT8    MipiCamCtrlLogic3_Wled1TorchMaxCurrent;  ///< Offset 1318    WLED1 Torch Max Current
  UINT8    MipiCamCtrlLogic3_Wled2FlashMaxCurrent;  ///< Offset 1319    WLED2 Flash Max Current
  UINT8    MipiCamCtrlLogic3_Wled2TorchMaxCurrent;  ///< Offset 1320    WLED2 Torch Max Current
  UINT8    MipiCamCtrlLogic3_SubPlatformId;         ///< Offset 1321    Sub Platform Id
  UINT8    MipiCamCtrlLogic3_Wled1Type;             ///< Offset 1322    WLED1 Type
  UINT8    MipiCamCtrlLogic3_Wled2Type;             ///< Offset 1323    WLED2 Type
  UINT8    MipiCamCtrlLogic3_PchClockSource;        ///< Offset 1324    PCH Clock source
  // Mipi Cam Link0 options
  UINT8    MipiCamLink0SensorModel;                 ///< Offset 1325    Sensor Model
  UINT8    MipiCamLink0UserHid[9];                  ///< Offset 1326    User defined HID ASCII character 0
                                                    ///< Offset 1334    User defined HID ASCII character 8
  UINT8    MipiCamLink0Pld;                         ///< Offset 1335    Camera Position
  UINT8    MipiCamLink0ModuleName[16];              ///< Offset 1336    Camera Module Name ASCII character 0
                                                    ///< Offset 1351    Camera Module Name ASCII character 15
  UINT8    MipiCamLink0I2cDevicesEnabled;           ///< Offset 1352    Number of I2C devices
  UINT8    MipiCamLink0I2cBus;                      ///< Offset 1353    I2C Serial Bus number
  UINT16   MipiCamLink0I2cAddrDev[12];              ///< Offset 1354    Address of I2C Device0 on Link0
                                                    ///< Offset 1356    Address of I2C Device1 on Link0
                                                    ///< Offset 1358    Address of I2C Device2 on Link0
                                                    ///< Offset 1360    Address of I2C Device3 on Link0
                                                    ///< Offset 1362    Address of I2C Device4 on Link0
                                                    ///< Offset 1364    Address of I2C Device5 on Link0
                                                    ///< Offset 1366    Address of I2C Device6 on Link0
                                                    ///< Offset 1368    Address of I2C Device7 on Link0
                                                    ///< Offset 1370    Address of I2C Device8 on Link0
                                                    ///< Offset 1372    Address of I2C Device9 on Link0
                                                    ///< Offset 1374    Address of I2C Device10 on Link0
                                                    ///< Offset 1376    Address of I2C Device11 on Link0
  UINT8    MipiCamLink0I2cDeviceType[12];           ///< Offset 1378    Type of I2C Device0 on Link0
                                                    ///< Offset 1379    Type of I2C Device1 on Link0
                                                    ///< Offset 1380    Type of I2C Device2 on Link0
                                                    ///< Offset 1381    Type of I2C Device3 on Link0
                                                    ///< Offset 1382    Type of I2C Device4 on Link0
                                                    ///< Offset 1383    Type of I2C Device5 on Link0
                                                    ///< Offset 1384    Type of I2C Device6 on Link0
                                                    ///< Offset 1385    Type of I2C Device7 on Link0
                                                    ///< Offset 1386    Type of I2C Device8 on Link0
                                                    ///< Offset 1387    Type of I2C Device9 on Link0
                                                    ///< Offset 1388    Type of I2C Device10 on Link0
                                                    ///< Offset 1389    Type of I2C Device11 on Link0
  UINT8    MipiCamLink0DD_Version;                  ///< Offset 1390    Version of SSDB structure
  UINT8    MipiCamLink0DD_CrdVersion;               ///< Offset 1391    Version of CRD
  UINT8    MipiCamLink0DD_LinkUsed;                 ///< Offset 1392    CSI2 Link used
  UINT8    MipiCamLink0DD_LaneUsed;                 ///< Offset 1393    MIPI-CSI2 Data Lane
  UINT8    MipiCamLink0DD_EepromType;               ///< Offset 1394    EEPROM Type
  UINT8    MipiCamLink0DD_VcmType;                  ///< Offset 1395    VCM Type
  UINT8    MipiCamLink0DD_FlashSupport;             ///< Offset 1396    Flash Support
  UINT8    MipiCamLink0DD_PrivacyLed;               ///< Offset 1397    Privacy LED
  UINT8    MipiCamLink0DD_Degree;                   ///< Offset 1398    Degree
  UINT32   MipiCamLink0DD_Mclk;                     ///< Offset 1399    MCLK
  UINT8    MipiCamLink0DD_ControlLogic;             ///< Offset 1403    Control Logic
  UINT8    MipiCamLink0DD_PmicPosition;             ///< Offset 1404    PMIC Position
  UINT8    MipiCamLink0DD_VoltageRail;              ///< Offset 1405    Voltage Rail
  // Mipi Cam Link1 options
  UINT8    MipiCamLink1SensorModel;                 ///< Offset 1406    Sensor Model
  UINT8    MipiCamLink1UserHid[9];                  ///< Offset 1407    User defined HID ASCII character 0
                                                    ///< Offset 1415    User defined HID ASCII character 8
  UINT8    MipiCamLink1Pld;                         ///< Offset 1416    Camera Position
  UINT8    MipiCamLink1ModuleName[16];              ///< Offset 1417    Camera Module Name ASCII character 0
                                                    ///< Offset 1432    Camera Module Name ASCII character 15
  UINT8    MipiCamLink1I2cDevicesEnabled;           ///< Offset 1433    Number of I2C devices
  UINT8    MipiCamLink1I2cBus;                      ///< Offset 1434    I2C Serial Bus number
  UINT16   MipiCamLink1I2cAddrDev[12];              ///< Offset 1435    Address of I2C Device0 on Link1
                                                    ///< Offset 1437    Address of I2C Device1 on Link1
                                                    ///< Offset 1439    Address of I2C Device2 on Link1
                                                    ///< Offset 1441    Address of I2C Device3 on Link1
                                                    ///< Offset 1443    Address of I2C Device4 on Link1
                                                    ///< Offset 1445    Address of I2C Device5 on Link1
                                                    ///< Offset 1447    Address of I2C Device6 on Link1
                                                    ///< Offset 1449    Address of I2C Device7 on Link1
                                                    ///< Offset 1451    Address of I2C Device8 on Link1
                                                    ///< Offset 1453    Address of I2C Device9 on Link1
                                                    ///< Offset 1455    Address of I2C Device10 on Link1
                                                    ///< Offset 1457    Address of I2C Device11 on Link1
  UINT8    MipiCamLink1I2cDeviceType[12];           ///< Offset 1459    Type of I2C Device0 on Link1
                                                    ///< Offset 1460    Type of I2C Device1 on Link1
                                                    ///< Offset 1461    Type of I2C Device2 on Link1
                                                    ///< Offset 1462    Type of I2C Device3 on Link1
                                                    ///< Offset 1463    Type of I2C Device4 on Link1
                                                    ///< Offset 1464    Type of I2C Device5 on Link1
                                                    ///< Offset 1465    Type of I2C Device6 on Link1
                                                    ///< Offset 1466    Type of I2C Device7 on Link1
                                                    ///< Offset 1467    Type of I2C Device8 on Link1
                                                    ///< Offset 1468    Type of I2C Device9 on Link1
                                                    ///< Offset 1469    Type of I2C Device10 on Link1
                                                    ///< Offset 1470    Type of I2C Device11 on Link1
  UINT8    MipiCamLink1DD_Version;                  ///< Offset 1471    Version of SSDB structure
  UINT8    MipiCamLink1DD_CrdVersion;               ///< Offset 1472    Version of CRD
  UINT8    MipiCamLink1DD_LinkUsed;                 ///< Offset 1473    CSI2 Link used
  UINT8    MipiCamLink1DD_LaneUsed;                 ///< Offset 1474    MIPI-CSI2 Data Lane
  UINT8    MipiCamLink1DD_EepromType;               ///< Offset 1475    EEPROM Type
  UINT8    MipiCamLink1DD_VcmType;                  ///< Offset 1476    VCM Type
  UINT8    MipiCamLink1DD_FlashSupport;             ///< Offset 1477    Flash Support
  UINT8    MipiCamLink1DD_PrivacyLed;               ///< Offset 1478    Privacy LED
  UINT8    MipiCamLink1DD_Degree;                   ///< Offset 1479    Degree
  UINT32   MipiCamLink1DD_Mclk;                     ///< Offset 1480    MCLK
  UINT8    MipiCamLink1DD_ControlLogic;             ///< Offset 1484    Control Logic
  UINT8    MipiCamLink1DD_PmicPosition;             ///< Offset 1485    PMIC Position
  UINT8    MipiCamLink1DD_VoltageRail;              ///< Offset 1486    Voltage Rail
  // Mipi Cam Link2 options
  UINT8    MipiCamLink2SensorModel;                 ///< Offset 1487    Sensor Model
  UINT8    MipiCamLink2UserHid[9];                  ///< Offset 1488    User defined HID ASCII character 0
                                                    ///< Offset 1496    User defined HID ASCII character 8
  UINT8    MipiCamLink2Pld;                         ///< Offset 1497    Camera Position
  UINT8    MipiCamLink2ModuleName[16];              ///< Offset 1498    Camera Module Name ASCII character 0
                                                    ///< Offset 1513    Camera Module Name ASCII character 15
  UINT8    MipiCamLink2I2cDevicesEnabled;           ///< Offset 1514    Number of I2C devices
  UINT8    MipiCamLink2I2cBus;                      ///< Offset 1515    I2C Serial Bus number
  UINT16   MipiCamLink2I2cAddrDev[12];              ///< Offset 1516    Address of I2C Device0 on Link2
                                                    ///< Offset 1518    Address of I2C Device1 on Link2
                                                    ///< Offset 1520    Address of I2C Device2 on Link2
                                                    ///< Offset 1522    Address of I2C Device3 on Link2
                                                    ///< Offset 1524    Address of I2C Device4 on Link2
                                                    ///< Offset 1526    Address of I2C Device5 on Link2
                                                    ///< Offset 1528    Address of I2C Device6 on Link2
                                                    ///< Offset 1530    Address of I2C Device7 on Link2
                                                    ///< Offset 1532    Address of I2C Device8 on Link2
                                                    ///< Offset 1534    Address of I2C Device9 on Link2
                                                    ///< Offset 1536    Address of I2C Device10 on Link2
                                                    ///< Offset 1538    Address of I2C Device11 on Link2
  UINT8    MipiCamLink2I2cDeviceType[12];           ///< Offset 1540    Type of I2C Device0 on Link2
                                                    ///< Offset 1541    Type of I2C Device1 on Link2
                                                    ///< Offset 1542    Type of I2C Device2 on Link2
                                                    ///< Offset 1543    Type of I2C Device3 on Link2
                                                    ///< Offset 1544    Type of I2C Device4 on Link2
                                                    ///< Offset 1545    Type of I2C Device5 on Link2
                                                    ///< Offset 1546    Type of I2C Device6 on Link2
                                                    ///< Offset 1547    Type of I2C Device7 on Link2
                                                    ///< Offset 1548    Type of I2C Device8 on Link2
                                                    ///< Offset 1549    Type of I2C Device9 on Link2
                                                    ///< Offset 1550    Type of I2C Device10 on Link2
                                                    ///< Offset 1551    Type of I2C Device11 on Link2
  UINT8    MipiCamLink2DD_Version;                  ///< Offset 1552    Version of SSDB structure
  UINT8    MipiCamLink2DD_CrdVersion;               ///< Offset 1553    Version of CRD
  UINT8    MipiCamLink2DD_LinkUsed;                 ///< Offset 1554    CSI2 Link used
  UINT8    MipiCamLink2DD_LaneUsed;                 ///< Offset 1555    MIPI-CSI2 Data Lane
  UINT8    MipiCamLink2DD_EepromType;               ///< Offset 1556    EEPROM Type
  UINT8    MipiCamLink2DD_VcmType;                  ///< Offset 1557    VCM Type
  UINT8    MipiCamLink2DD_FlashSupport;             ///< Offset 1558    Flash Support
  UINT8    MipiCamLink2DD_PrivacyLed;               ///< Offset 1559    Privacy LED
  UINT8    MipiCamLink2DD_Degree;                   ///< Offset 1560    Degree
  UINT32   MipiCamLink2DD_Mclk;                     ///< Offset 1561    MCLK
  UINT8    MipiCamLink2DD_ControlLogic;             ///< Offset 1565    Control Logic
  UINT8    MipiCamLink2DD_PmicPosition;             ///< Offset 1566    PMIC Position
  UINT8    MipiCamLink2DD_VoltageRail;              ///< Offset 1567    Voltage Rail
  // Mipi Cam Link3 options
  UINT8    MipiCamLink3SensorModel;                 ///< Offset 1568    Sensor Model
  UINT8    MipiCamLink3UserHid[9];                  ///< Offset 1569    User defined HID ASCII character 0
                                                    ///< Offset 1577    User defined HID ASCII character 8
  UINT8    MipiCamLink3Pld;                         ///< Offset 1578    Camera Position
  UINT8    MipiCamLink3ModuleName[16];              ///< Offset 1579    Camera Module Name ASCII character 0
                                                    ///< Offset 1594    Camera Module Name ASCII character 15
  UINT8    MipiCamLink3I2cDevicesEnabled;           ///< Offset 1595    Number of I2C devices
  UINT8    MipiCamLink3I2cBus;                      ///< Offset 1596    I2C Serial Bus number
  UINT16   MipiCamLink3I2cAddrDev[12];              ///< Offset 1597    Address of I2C Device0 on Link3
                                                    ///< Offset 1599    Address of I2C Device1 on Link3
                                                    ///< Offset 1601    Address of I2C Device2 on Link3
                                                    ///< Offset 1603    Address of I2C Device3 on Link3
                                                    ///< Offset 1605    Address of I2C Device4 on Link3
                                                    ///< Offset 1607    Address of I2C Device5 on Link3
                                                    ///< Offset 1609    Address of I2C Device6 on Link3
                                                    ///< Offset 1611    Address of I2C Device7 on Link3
                                                    ///< Offset 1613    Address of I2C Device8 on Link3
                                                    ///< Offset 1615    Address of I2C Device9 on Link3
                                                    ///< Offset 1617    Address of I2C Device10 on Link3
                                                    ///< Offset 1619    Address of I2C Device11 on Link3
  UINT8    MipiCamLink3I2cDeviceType[12];           ///< Offset 1621    Type of I2C Device0 on Link3
                                                    ///< Offset 1622    Type of I2C Device1 on Link3
                                                    ///< Offset 1623    Type of I2C Device2 on Link3
                                                    ///< Offset 1624    Type of I2C Device3 on Link3
                                                    ///< Offset 1625    Type of I2C Device4 on Link3
                                                    ///< Offset 1626    Type of I2C Device5 on Link3
                                                    ///< Offset 1627    Type of I2C Device6 on Link3
                                                    ///< Offset 1628    Type of I2C Device7 on Link3
                                                    ///< Offset 1629    Type of I2C Device8 on Link3
                                                    ///< Offset 1630    Type of I2C Device9 on Link3
                                                    ///< Offset 1631    Type of I2C Device10 on Link3
                                                    ///< Offset 1632    Type of I2C Device11 on Link3
  UINT8    MipiCamLink3DD_Version;                  ///< Offset 1633    Version of SSDB structure
  UINT8    MipiCamLink3DD_CrdVersion;               ///< Offset 1634    Version of CRD
  UINT8    MipiCamLink3DD_LinkUsed;                 ///< Offset 1635    CSI2 Link used
  UINT8    MipiCamLink3DD_LaneUsed;                 ///< Offset 1636    MIPI-CSI2 Data Lane
  UINT8    MipiCamLink3DD_EepromType;               ///< Offset 1637    EEPROM Type
  UINT8    MipiCamLink3DD_VcmType;                  ///< Offset 1638    VCM Type
  UINT8    MipiCamLink3DD_FlashSupport;             ///< Offset 1639    Flash Support
  UINT8    MipiCamLink3DD_PrivacyLed;               ///< Offset 1640    Privacy LED
  UINT8    MipiCamLink3DD_Degree;                   ///< Offset 1641    Degree
  UINT32   MipiCamLink3DD_Mclk;                     ///< Offset 1642    MCLK
  UINT8    MipiCamLink3DD_ControlLogic;             ///< Offset 1646    Control Logic
  UINT8    MipiCamLink3DD_PmicPosition;             ///< Offset 1647    PMIC Position
  UINT8    MipiCamLink3DD_VoltageRail;              ///< Offset 1648    Voltage Rail
  UINT8    Reserved16[1];                           ///< Offset 1649:1649
  UINT8    PciDelayOptimizationEcr;                 ///< Offset 1650    
  UINT8    I2SC;                                    ///< Offset 1651    HD Audio I2S Codec Selection
  UINT32   I2SI;                                    ///< Offset 1652    HD Audio I2S Codec Interrupt Pin
  UINT8    I2SB;                                    ///< Offset 1656    HD Audio I2S Codec Connection to I2C bus controller instance (I2C[0-5])
  UINT8    OemDesignVariable0;                      ///< Offset 1657    DPTF Oem Design Variables
  UINT8    OemDesignVariable1;                      ///< Offset 1658    DPTF Oem Design Variables
  UINT8    OemDesignVariable2;                      ///< Offset 1659    DPTF Oem Design Variables
  UINT8    OemDesignVariable3;                      ///< Offset 1660    DPTF Oem Design Variables
  UINT8    OemDesignVariable4;                      ///< Offset 1661    DPTF Oem Design Variables
  UINT8    OemDesignVariable5;                      ///< Offset 1662    DPTF Oem Design Variables
  UINT32   UsbTypeCOpBaseAddr;                      ///< Offset 1663    USB Type C Opregion base address
  UINT8    Reserved17[5];                           ///< Offset 1667:1671
  UINT8    WirelessCharging;                        ///< Offset 1672    WirelessCharging
  // RTD3 Settings
  UINT8    Reserved18[7];                           ///< Offset 1673:1679
  UINT32   HdaDspPpModuleMask;                      ///< Offset 1680    HD-Audio DSP Post-Processing Module Mask
  UINT64   HdaDspPpModCustomGuid1Low;               ///< Offset 1684    HDA PP module custom GUID 1 - first 64bit  [0-63]
  UINT64   HdaDspPpModCustomGuid1High;              ///< Offset 1692    HDA PP module custom GUID 1 - second 64bit [64-127]
  UINT64   HdaDspPpModCustomGuid2Low;               ///< Offset 1700    HDA PP module custom GUID 2 - first 64bit  [0-63]
  UINT64   HdaDspPpModCustomGuid2High;              ///< Offset 1708    HDA PP module custom GUID 2 - second 64bit [64-127]
  UINT64   HdaDspPpModCustomGuid3Low;               ///< Offset 1716    HDA PP module custom GUID 3 - first 64bit  [0-63]
  UINT64   HdaDspPpModCustomGuid3High;              ///< Offset 1724    HDA PP module custom GUID 3 - second 64bit [64-127]
  UINT8    HidEventFilterEnable;                    ///< Offset 1732    HID Event Filter Driver enable
  UINT8    XdciFnEnable;                            ///< Offset 1733    XDCI Enable/Disable status
  UINT8    WrdsWiFiSarEnable;                       ///< Offset 1734    WrdsWiFiSarEnable
  UINT8    WrdsWiFiSarTxPowerSet1Limit1;            ///< Offset 1735    WrdsWiFiSarTxPowerSet1Limit1
  UINT8    WrdsWiFiSarTxPowerSet1Limit2;            ///< Offset 1736    WrdsWiFiSarTxPowerSet1Limit2
  UINT8    WrdsWiFiSarTxPowerSet1Limit3;            ///< Offset 1737    WrdsWiFiSarTxPowerSet1Limit3
  UINT8    WrdsWiFiSarTxPowerSet1Limit4;            ///< Offset 1738    WrdsWiFiSarTxPowerSet1Limit4
  UINT8    WrdsWiFiSarTxPowerSet1Limit5;            ///< Offset 1739    WrdsWiFiSarTxPowerSet1Limit5
  UINT8    WrdsWiFiSarTxPowerSet1Limit6;            ///< Offset 1740    WrdsWiFiSarTxPowerSet1Limit6
  UINT8    WrdsWiFiSarTxPowerSet1Limit7;            ///< Offset 1741    WrdsWiFiSarTxPowerSet1Limit7
  UINT8    WrdsWiFiSarTxPowerSet1Limit8;            ///< Offset 1742    WrdsWiFiSarTxPowerSet1Limit8
  UINT8    WrdsWiFiSarTxPowerSet1Limit9;            ///< Offset 1743    WrdsWiFiSarTxPowerSet1Limit9
  UINT8    WrdsWiFiSarTxPowerSet1Limit10;           ///< Offset 1744    WrdsWiFiSarTxPowerSet1Limit10
  UINT8    EnableVoltageMargining;                  ///< Offset 1745    Enable Voltage Margining
  UINT16   DStateHSPort;                            ///< Offset 1746    D-State for xHCI HS port(BIT0:USB HS Port0 ~ BIT15:USB HS Port15)
  UINT16   DStateSSPort;                            ///< Offset 1748    D-State for xHCI SS port(BIT0:USB SS Port0 ~ BIT15:USB SS Port15)
  UINT8    DStateSataPort;                          ///< Offset 1750    D-State for SATA port(BIT0:SATA Port0 ~ BIT7:SATA Port7)
  UINT8    WigigRfe;                                ///< Offset 1751    WigigRfe
  UINT8    WiGigRfeCh1;                             ///< Offset 1752    WiGigRfeCh1
  UINT8    WiGigRfeCh2;                             ///< Offset 1753    WiGigRfeCh2
  UINT8    WiGigRfeCh3;                             ///< Offset 1754    WiGigRfeCh3
  UINT8    WiGigRfeCh4;                             ///< Offset 1755    WiGigRfeCh4
  UINT32   AwvClassIndex;                           ///< Offset 1756    AwvClassIndex
  UINT8    EwrdWiFiDynamicSarEnable;                ///< Offset 1760    EwrdWiFiDynamicSarEnable
  UINT8    EwrdWiFiDynamicSarRangeSets;             ///< Offset 1761    EwrdWiFiDynamicSarRangeSets
  UINT8    EwrdWiFiSarTxPowerSet2Limit1;            ///< Offset 1762    EwrdWiFiSarTxPowerSet2Limit1
  UINT8    EwrdWiFiSarTxPowerSet2Limit2;            ///< Offset 1763    EwrdWiFiSarTxPowerSet2Limit2
  UINT8    EwrdWiFiSarTxPowerSet2Limit3;            ///< Offset 1764    EwrdWiFiSarTxPowerSet2Limit3
  UINT8    EwrdWiFiSarTxPowerSet2Limit4;            ///< Offset 1765    EwrdWiFiSarTxPowerSet2Limit4
  UINT8    EwrdWiFiSarTxPowerSet2Limit5;            ///< Offset 1766    EwrdWiFiSarTxPowerSet2Limit5
  UINT8    EwrdWiFiSarTxPowerSet2Limit6;            ///< Offset 1767    EwrdWiFiSarTxPowerSet2Limit6
  UINT8    EwrdWiFiSarTxPowerSet2Limit7;            ///< Offset 1768    EwrdWiFiSarTxPowerSet2Limit7
  UINT8    EwrdWiFiSarTxPowerSet2Limit8;            ///< Offset 1769    EwrdWiFiSarTxPowerSet2Limit8
  UINT8    EwrdWiFiSarTxPowerSet2Limit9;            ///< Offset 1770    EwrdWiFiSarTxPowerSet2Limit9
  UINT8    EwrdWiFiSarTxPowerSet2Limit10;           ///< Offset 1771    EwrdWiFiSarTxPowerSet2Limit10
  UINT8    EwrdWiFiSarTxPowerSet3Limit1;            ///< Offset 1772    EwrdWiFiSarTxPowerSet3Limit1
  UINT8    EwrdWiFiSarTxPowerSet3Limit2;            ///< Offset 1773    EwrdWiFiSarTxPowerSet3Limit2
  UINT8    EwrdWiFiSarTxPowerSet3Limit3;            ///< Offset 1774    EwrdWiFiSarTxPowerSet3Limit3
  UINT8    EwrdWiFiSarTxPowerSet3Limit4;            ///< Offset 1775    EwrdWiFiSarTxPowerSet3Limit4
  UINT8    EwrdWiFiSarTxPowerSet3Limit5;            ///< Offset 1776    EwrdWiFiSarTxPowerSet3Limit5
  UINT8    EwrdWiFiSarTxPowerSet3Limit6;            ///< Offset 1777    EwrdWiFiSarTxPowerSet3Limit6
  UINT8    EwrdWiFiSarTxPowerSet3Limit7;            ///< Offset 1778    EwrdWiFiSarTxPowerSet3Limit7
  UINT8    EwrdWiFiSarTxPowerSet3Limit8;            ///< Offset 1779    EwrdWiFiSarTxPowerSet3Limit8
  UINT8    EwrdWiFiSarTxPowerSet3Limit9;            ///< Offset 1780    EwrdWiFiSarTxPowerSet3Limit9
  UINT8    EwrdWiFiSarTxPowerSet3Limit10;           ///< Offset 1781    EwrdWiFiSarTxPowerSet3Limit10
  UINT8    EwrdWiFiSarTxPowerSet4Limit1;            ///< Offset 1782    EwrdWiFiSarTxPowerSet4Limit1
  UINT8    EwrdWiFiSarTxPowerSet4Limit2;            ///< Offset 1783    EwrdWiFiSarTxPowerSet4Limit2
  UINT8    EwrdWiFiSarTxPowerSet4Limit3;            ///< Offset 1784    EwrdWiFiSarTxPowerSet4Limit3
  UINT8    EwrdWiFiSarTxPowerSet4Limit4;            ///< Offset 1785    EwrdWiFiSarTxPowerSet4Limit4
  UINT8    EwrdWiFiSarTxPowerSet4Limit5;            ///< Offset 1786    EwrdWiFiSarTxPowerSet4Limit5
  UINT8    EwrdWiFiSarTxPowerSet4Limit6;            ///< Offset 1787    EwrdWiFiSarTxPowerSet4Limit6
  UINT8    EwrdWiFiSarTxPowerSet4Limit7;            ///< Offset 1788    EwrdWiFiSarTxPowerSet4Limit7
  UINT8    EwrdWiFiSarTxPowerSet4Limit8;            ///< Offset 1789    EwrdWiFiSarTxPowerSet4Limit8
  UINT8    EwrdWiFiSarTxPowerSet4Limit9;            ///< Offset 1790    EwrdWiFiSarTxPowerSet4Limit9
  UINT8    EwrdWiFiSarTxPowerSet4Limit10;           ///< Offset 1791    EwrdWiFiSarTxPowerSet4Limit10
  UINT8    WgdsWiFiSarDeltaGroup1PowerMax1;         ///< Offset 1792    WgdsWiFiSarDeltaGroup1PowerMax1
  UINT8    WgdsWiFiSarDeltaGroup1PowerChainA1;      ///< Offset 1793    WgdsWiFiSarDeltaGroup1PowerChainA1
  UINT8    WgdsWiFiSarDeltaGroup1PowerChainB1;      ///< Offset 1794    WgdsWiFiSarDeltaGroup1PowerChainB1
  UINT8    WgdsWiFiSarDeltaGroup1PowerMax2;         ///< Offset 1795    WgdsWiFiSarDeltaGroup1PowerMax2
  UINT8    WgdsWiFiSarDeltaGroup1PowerChainA2;      ///< Offset 1796    WgdsWiFiSarDeltaGroup1PowerChainA2
  UINT8    WgdsWiFiSarDeltaGroup1PowerChainB2;      ///< Offset 1797    WgdsWiFiSarDeltaGroup1PowerChainB2
  UINT8    WgdsWiFiSarDeltaGroup2PowerMax1;         ///< Offset 1798    WgdsWiFiSarDeltaGroup2PowerMax1
  UINT8    WgdsWiFiSarDeltaGroup2PowerChainA1;      ///< Offset 1799    WgdsWiFiSarDeltaGroup2PowerChainA1
  UINT8    WgdsWiFiSarDeltaGroup2PowerChainB1;      ///< Offset 1800    WgdsWiFiSarDeltaGroup2PowerChainB1
  UINT8    WgdsWiFiSarDeltaGroup2PowerMax2;         ///< Offset 1801    WgdsWiFiSarDeltaGroup2PowerMax2
  UINT8    WgdsWiFiSarDeltaGroup2PowerChainA2;      ///< Offset 1802    WgdsWiFiSarDeltaGroup2PowerChainA2
  UINT8    WgdsWiFiSarDeltaGroup2PowerChainB2;      ///< Offset 1803    WgdsWiFiSarDeltaGroup2PowerChainB2
  UINT8    WgdsWiFiSarDeltaGroup3PowerMax1;         ///< Offset 1804    WgdsWiFiSarDeltaGroup3PowerMax1
  UINT8    WgdsWiFiSarDeltaGroup3PowerChainA1;      ///< Offset 1805    WgdsWiFiSarDeltaGroup3PowerChainA1
  UINT8    WgdsWiFiSarDeltaGroup3PowerChainB1;      ///< Offset 1806    WgdsWiFiSarDeltaGroup3PowerChainB1
  UINT8    WgdsWiFiSarDeltaGroup3PowerMax2;         ///< Offset 1807    WgdsWiFiSarDeltaGroup3PowerMax2
  UINT8    WgdsWiFiSarDeltaGroup3PowerChainA2;      ///< Offset 1808    WgdsWiFiSarDeltaGroup3PowerChainA2
  UINT8    WgdsWiFiSarDeltaGroup3PowerChainB2;      ///< Offset 1809    WgdsWiFiSarDeltaGroup3PowerChainB2
  UINT8    Reserved19[32];                          ///< Offset 1810:1841
  // Reserved for Groups 4 to 9, each needs 6 bytes and total 36 bytes reserved
  UINT8    WiFiDynamicSarAntennaACurrentSet;        ///< Offset 1842    WiFiDynamicSarAntennaACurrentSet
  UINT8    WiFiDynamicSarAntennaBCurrentSet;        ///< Offset 1843    WiFiDynamicSarAntennaBCurrentSet
  UINT8    BluetoothSar;                            ///< Offset 1844    BluetoothSar
  UINT8    BluetoothSarBr;                          ///< Offset 1845    BluetoothSarBr
  UINT8    BluetoothSarEdr2;                        ///< Offset 1846    BluetoothSarEdr2
  UINT8    BluetoothSarEdr3;                        ///< Offset 1847    BluetoothSarEdr3
  UINT8    BluetoothSarLe;                          ///< Offset 1848    BluetoothSarLe
  UINT8    Reserved20[4];                           ///< Offset 1849:1852
  // Reserved for Bluetooth Sar future use
  UINT8    CoExistenceManager;                      ///< Offset 1853    CoExistenceManager
  UINT8    RunTimeVmControl;                        ///< Offset 1854    RunTime VM Control
  //
  //Feature Specific Data Bits
  //
  UINT8    UsbTypeCSupport;                         ///< Offset 1855    USB Type C Supported
  UINT32   HebcValue;                               ///< Offset 1856    HebcValue
  UINT8    PcdBatteryPresent;                       ///< Offset 1860    Battery Present - Bit0: Real Battery is supported on this platform. Bit1: Virtual Battery is supported on this platform.
  UINT8    PcdTsOnDimmTemperature;                  ///< Offset 1861    TS-on-DIMM temperature
  UINT8    Reserved21[3];                           ///< Offset 1862:1864
  UINT8    PcdRealBattery1Control;                  ///< Offset 1865    Real Battery 1 Control
  UINT8    PcdRealBattery2Control;                  ///< Offset 1866    Real Battery 2 Control
  UINT8    PcdMipiCamSensor;                        ///< Offset 1867    Mipi Camera Sensor
  UINT8    PcdNCT6776FCOM;                          ///< Offset 1868    NCT6776F COM
  UINT8    PcdNCT6776FSIO;                          ///< Offset 1869    NCT6776F SIO
  UINT8    PcdNCT6776FHWMON;                        ///< Offset 1870    NCT6776F HWMON
  UINT8    PcdH8S2113SIO;                           ///< Offset 1871    H8S2113 SIO
  UINT8    PcdZPoddConfig;                          ///< Offset 1872    ZPODD
  UINT8    PcdRGBCameraAdr;                         ///< Offset 1873    RGB Camera Address
  UINT8    PcdDepthCameraAdr;                       ///< Offset 1874    Depth Camera Addresy
  UINT32   PcdSmcRuntimeSciPin;                     ///< Offset 1875    SMC Runtime Sci Pin
  UINT8    PcdConvertableDockSupport;               ///< Offset 1879    Convertable Dock Support
  UINT8    PcdEcHotKeyF3Support;                    ///< Offset 1880    Ec Hotkey F3 Support
  UINT8    PcdEcHotKeyF4Support;                    ///< Offset 1881    Ec Hotkey F4 Support
  UINT8    PcdEcHotKeyF5Support;                    ///< Offset 1882    Ec Hotkey F5 Support
  UINT8    PcdEcHotKeyF6Support;                    ///< Offset 1883    Ec Hotkey F6 Support
  UINT8    PcdEcHotKeyF7Support;                    ///< Offset 1884    Ec Hotkey F7 Support
  UINT8    PcdEcHotKeyF8Support;                    ///< Offset 1885    Ec Hotkey F8 Support
  UINT8    PcdVirtualButtonVolumeUpSupport;         ///< Offset 1886    Virtual Button Volume Up Support
  UINT8    PcdVirtualButtonVolumeDownSupport;       ///< Offset 1887    Virtual Button Volume Down Support
  UINT8    PcdVirtualButtonHomeButtonSupport;       ///< Offset 1888    Virtual Button Home Button Support
  UINT8    PcdVirtualButtonRotationLockSupport;     ///< Offset 1889    Virtual Button Rotation Lock Support
  UINT8    PcdSlateModeSwitchSupport;               ///< Offset 1890    Slate Mode Switch Support
  UINT8    PcdVirtualGpioButtonSupport;             ///< Offset 1891    Virtual Button Support
  UINT8    PcdAcDcAutoSwitchSupport;                ///< Offset 1892    Ac Dc Auto Switch Support
  UINT32   PcdPmPowerButtonGpioPin;                 ///< Offset 1893    Pm Power Button Gpio Pin
  UINT8    PcdAcpiEnableAllButtonSupport;           ///< Offset 1897    Acpi Enable All Button Support
  UINT8    PcdAcpiHidDriverButtonSupport;           ///< Offset 1898    Acpi Hid Driver Button Support
  UINT8    DisplayDepthLowerLimit;                  ///< Offset 1899    DPTF Display Depth Lower Limit in percent
  UINT8    DisplayDepthUpperLimit;                  ///< Offset 1900    DPTF Display Depth Upper Limit in percent
  UINT8    PepWiGigF1;                              ///< Offset 1901    PEP F1 constraints for WiGig device
  UINT8    ThermalSamplingPeriodWrls;               ///< Offset 1902    ThermalSamplingPeriodWrls
  UINT32   EcLowPowerModeGpioPin;                   ///< Offset 1903    EcLowPowerModeGpioPin
  UINT32   EcSmiGpioPin;                            ///< Offset 1907    EcSmiGpioPin
  UINT8    WakeOnWiGigSupport;                      ///< Offset 1911    Wake on S3-S4 WiGig Docking Support
  //
  // UCMC setup option, GPIO Pad
  //
  UINT8    UCMS;                                    ///< Offset 1912    Option to select UCSI/UCMC device
  UINT32   UcmcPort1Gpio;                           ///< Offset 1913    Gpio for UCMC Port 1 Interrupt
  UINT32   UcmcPort2Gpio;                           ///< Offset 1917    Gpio for UCMC Port 2 Interrupt
  UINT8    Reserved22[24];                          ///< Offset 1921:1944
  UINT8    EnablePchFivrParticipant;                ///< Offset 1945    EnablePchFivrParticipant
  UINT8    Reserved23[5];                           ///< Offset 1946:1950
  UINT8    SerialPortAcpiDebug;                     ///< Offset 1951    Serial Port ACPI debug
  UINT8    Ufp2DfpGlobalFlag;                       ///< Offset 1952    Upstream Facing port or Downstream Facing port Global Flag from LPC EC
  UINT8    Ufp2DfpUsbPort;                          ///< Offset 1953    Upstream Facing port or Downstream Facing port number from LPC EC
  UINT8    DbcGlobalFlag;                           ///< Offset 1954    Debug Mode Global Flag from LPC EC
  UINT8    DbcUsbPort;                              ///< Offset 1955    Debug Mode USB Port Number from LPC EC
  UINT8    TotalTypeCPorts;                         ///< Offset 1956    Total Number of type C ports that are supported by platform
  UINT8    UsbTypeCPort1;                           ///< Offset 1957    Type C Connector 1  Port mapping within the controller the port exposed
  UINT8    UsbTypeCPort1Pch;                        ///< Offset 1958    Type C Connector 1  Port mapping within the PCH controller (If Split mode supported)
  UINT8    UsbCPort1Proterties;                     ///< Offset 1959    Type C Connector 1  Portperties Split Support/Controller(PCH/TBT/CPU)/Root port (vaild for TBT)
  UINT8    UsbTypeCPort2;                           ///< Offset 1960    Type C Connector 2  Port mapping within the controller the port exposed
  UINT8    UsbTypeCPort2Pch;                        ///< Offset 1961    Type C Connector 2  Port mapping within the PCH controller (If Split mode supported)
  UINT8    UsbCPort2Proterties;                     ///< Offset 1962    Type C Connector 2  Portperties Split Support/Controller(PCH/TBT/CPU)/Root port (vaild for TBT)
  UINT8    UsbTypeCPort3;                           ///< Offset 1963    Type C Connector 3  Port mapping within the controller the port exposed
  UINT8    UsbTypeCPort3Pch;                        ///< Offset 1964    Type C Connector 3  Port mapping within the PCH controller (If Split mode supported)
  UINT8    UsbCPort3Proterties;                     ///< Offset 1965    Type C Connector 3  Portperties Split Support/Controller(PCH/TBT/CPU)/Root port (vaild for TBT)
  UINT8    UsbTypeCPort4;                           ///< Offset 1966    Type C Connector 4  Port mapping within the controller the port exposed
  UINT8    UsbTypeCPort4Pch;                        ///< Offset 1967    Type C Connector 4  Port mapping within the PCH controller (If Split mode supported)
  UINT8    UsbCPort4Proterties;                     ///< Offset 1968    Type C Connector 4  Portperties Split Support/Controller(PCH/TBT/CPU)/Root port (vaild for TBT)
  UINT8    UsbTypeCPort5;                           ///< Offset 1969    Type C Connector 5  Port mapping within the controller the port exposed
  UINT8    UsbTypeCPort5Pch;                        ///< Offset 1970    Type C Connector 5  Port mapping within the PCH controller (If Split mode supported)
  UINT8    UsbCPort5Proterties;                     ///< Offset 1971    Type C Connector 5  Portperties Split Support/Controller(PCH/TBT/CPU)/Root port (vaild for TBT)
  UINT8    UsbTypeCPort6;                           ///< Offset 1972    Type C Connector 6  Port mapping within the controller the port exposed
  UINT8    UsbTypeCPort6Pch;                        ///< Offset 1973    Type C Connector 6  Port mapping within the PCH controller (If Split mode supported)
  UINT8    UsbCPort6Proterties;                     ///< Offset 1974    Type C Connector 6  Portperties Split Support/Controller(PCH/TBT/CPU)/Root port (vaild for TBT)
  UINT8    AntennaDiversity;                        ///< Offset 1975    AntennaDiversity
  UINT8    BluetoothSarLe2Mhz;                      ///< Offset 1976    BluetoothSarLe2Mhz
  UINT8    BluetoothSarLeLr;                        ///< Offset 1977    BluetoothSarLeLr
} PLATFORM_NVS_AREA;

#pragma pack(pop)
typedef struct _PLATFORM_NVS_AREA_PROTOCOL {
  PLATFORM_NVS_AREA     *Area;
} PLATFORM_NVS_AREA_PROTOCOL;



#pragma pack (push,1)
typedef struct {
  UINT8    Revision;                                ///< Offset 0       CPU GlobalNvs Revision
  UINT32   PpmFlags;                                ///< Offset 1       PPM Flags Values
  UINT8    Reserved0[1];                            ///< Offset 5:5
  UINT8    AutoCriticalTripPoint;                   ///< Offset 6       Auto Critical Trip Point
  UINT8    AutoPassiveTripPoint;                    ///< Offset 7       Auto Passive Trip Point
  UINT8    AutoActiveTripPoint;                     ///< Offset 8       Auto Active Trip Point
  UINT32   Cpuid;                                   ///< Offset 9       CPUID
  UINT8    ConfigurablePpc;                         ///< Offset 13      Boot Mode vlues for _PPC
  UINT8    CtdpLevelsSupported;                     ///< Offset 14      ConfigTdp Number Of Levels
  UINT8    ConfigTdpBootModeIndex;                  ///< Offset 15      CTDP Boot Mode Index
  UINT16   CtdpPowerLimit1[3];                      ///< Offset 16      CTDP Level 0 Power Limit1
                                                    ///< Offset 18      CTDP Level 1 Power Limit1
                                                    ///< Offset 20      CTDP Level 2 Power Limit1
  UINT16   CtdpPowerLimit2[3];                      ///< Offset 22      CTDP Level 0 Power Limit2
                                                    ///< Offset 24      CTDP Level 1 Power Limit2
                                                    ///< Offset 26      CTDP Level 2 Power Limit2
  UINT8    CtdpPowerLimitWindow[3];                 ///< Offset 28      CTDP Level 0 Power Limit1 Time Window
                                                    ///< Offset 29      CTDP Level 1 Power Limit1 Time Window
                                                    ///< Offset 30      CTDP Level 2 Power Limit1 Time Window
  UINT8    CtdpCtc[3];                              ///< Offset 31      CTDP Level 0 CTC
                                                    ///< Offset 32      CTDP Level 1 CTC
                                                    ///< Offset 33      CTDP Level 2 CTC
  UINT8    CtdpTar[3];                              ///< Offset 34      CTDP Level 0 TAR
                                                    ///< Offset 35      CTDP Level 1 TAR
                                                    ///< Offset 36      CTDP Level 2 TAR
  UINT8    CtdpPpc[3];                              ///< Offset 37      CTDP Level 0 PPC
                                                    ///< Offset 38      CTDP Level 1 PPC
                                                    ///< Offset 39      CTDP Level 2 PPC
  UINT8    Reserved1[1];                            ///< Offset 40:40
  UINT8    C6MwaitValue;                            ///< Offset 41      Mwait Hint value for C6
  UINT8    C7MwaitValue;                            ///< Offset 42      Mwait Hint value for C7/C7s
  UINT8    CDMwaitValue;                            ///< Offset 43      Mwait Hint value for C7/C8/C9/C10
  UINT8    Reserved2[2];                            ///< Offset 44:45
  UINT16   C6Latency;                               ///< Offset 46      Latency Value for C6
  UINT16   C7Latency;                               ///< Offset 48      Latency Value for C7/C7S
  UINT16   CDLatency;                               ///< Offset 50      Latency Value for C8/C9/C10
  UINT16   CDIOLevel;                               ///< Offset 52      IO LVL value for C8/C9/C10
  UINT16   CDPowerValue;                            ///< Offset 54      Power value for C8/C9/C10
  UINT8    MiscPowerManagementFlags;                ///< Offset 56      MiscPowerManagementFlags
  UINT8    EnableDigitalThermalSensor;              ///< Offset 57      Digital Thermal Sensor Enable
  UINT8    DigitalThermalSensorSmiFunction;         ///< Offset 58      DTS SMI Function Call via DTS IO Trap
  UINT8    PackageDTSTemperature;                   ///< Offset 59      Package Temperature or Max Core temperature.
  UINT8    IsPackageTempMSRAvailable;               ///< Offset 60      Package Temperature MSR available
  UINT16   DtsIoTrapAddress;                        ///< Offset 61      DTS IO trap Address
  UINT8    DtsIoTrapLength;                         ///< Offset 63      DTS IO trap Length
  UINT8    DtsAcpiEnable;                           ///< Offset 64      DTS is in ACPI Mode Enabled
  UINT8    SgxStatus;                               ///< Offset 65      SGX Status
  UINT64   EpcBaseAddress;                          ///< Offset 66      EPC Base Address
  UINT64   EpcLength;                               ///< Offset 74      EPC Length
  UINT8    HwpVersion;                              ///< Offset 82      HWP Version
  UINT8    HwpInterruptStatus;                      ///< Offset 83      HWP Interrupt Status
  UINT8    DtsInterruptStatus;                      ///< Offset 84      DTS Interrupt Status
  UINT8    HwpSmi;                                  ///< Offset 85      SMI to setup HWP LVT tables
  UINT8    LowestMaxPerf;                           ///< Offset 86      Max ratio of the slowest core.
  UINT8    EnableItbm;                              ///< Offset 87      Enable/Disable Intel Turbo Boost Max Technology 3.0.
  UINT8    EnableItbmDriver;                        ///< Offset 88      Enable/Disable Intel Turbo Boost Max Technology 3.0 Driver.
  UINT8    ItbmInterruptStatus;                     ///< Offset 89      Intel Turbo Boost Max Technology 3.0 interrupt status.
  UINT8    ItbmSmi;                                 ///< Offset 90      SMI to resume periodic SMM for Intel Turbo Boost Max Technology 3.0.
  UINT8    OcBins;                                  ///< Offset 91      Indicates bins of Oc support. MSR 194h FLEX_RATIO Bits (19:17)
} CPU_NVS_AREA;

#pragma pack(pop)
typedef struct {
  CPU_NVS_AREA                          *Area;
} CPU_NVS_AREA_PROTOCOL;


typedef struct _CPU_GLOBAL_NVS_AREA_PROTOCOL CPU_GLOBAL_NVS_AREA_PROTOCOL;

//
// Processor GlobalNvs Revisions
//
#define CPU_GLOBAL_NVS_AREA_REVISION 2

#pragma pack(1)
///
/// Config TDP level settings.
///
typedef struct {
  UINT16 CtdpPowerLimit1;      ///< CTDP Power Limit1
  UINT16 CtdpPowerLimit2;      ///< CTDP Power Limit2
  UINT8  CtdpPowerLimitWindow; ///< CTDP Power Limit Time Window
  UINT8  CtdpCtc;              ///< CTDP CTC
  UINT8  CtdpTar;              ///< CTDP TAR
  UINT8  CtdpPpc;              ///< CTDP PPC
} PPM_CTDP_LEVEL_SETTINGS;

///
/// Global NVS Area definition
///
typedef struct {
  /**
  This member specifies the revision of the CPU_GLOBAL_NVS_AREA. This field is used to indicate backward
  compatible changes to the NVS AREA. Any such changes to this PPI will result in an update in the revision number.

  <b>Revision 1</b>:
   - Initial version.
  **/
  UINT8  Revision;                 ///< (0) CPU GlobalNvs Revision
  //
  // PPM Flag Values
  //
  UINT32 PpmFlags;                 ///< (1-4) PPM Flags
  UINT8  Reserved;                 ///< (5) Reserved
  //
  // Thermal Configuration Values
  //
  UINT8  AutoCriticalTripPoint;    ///< (6) Auto Critical Trip Point
  UINT8  AutoPassiveTripPoint;     ///< (7) Auto Passive Trip Point
  UINT8  AutoActiveTripPoint;      ///< (8) Auto Active Trip Point
  UINT32 Cpuid;                    ///< (9) CPUID
  //
  // ConfigTDP Values
  //
  UINT8 ConfigurablePpc;           ///< (13) Boot Mode vlues for _PPC
  //
  // ConfigTDP Level settngs
  //
  UINT8 CtdpLevelsSupported;       ///< (14) ConfigTdp Number Of Levels
  UINT8 ConfigTdpBootModeIndex;    ///< (15) CTDP Boot Mode Index
  ///
  /// (16) CTDP Level 0 Power Limit1
  /// (18) CTDP Level 0 Power Limit2
  /// (20) CTDP Level 0 Power Limit1 Time Window
  /// (21) CTDP Level 0 CTC
  /// (22) CTDP Level 0 TAR
  /// (23) CTDP Level 0 PPC
  /// (24) CTDP Level 1 Power Limit1
  /// (26) CTDP Level 1 Power Limit2
  /// (28) CTDP Level 1 Power Limit1 Time Window
  /// (29) CTDP Level 1 CTC
  /// (30) CTDP Level 1 TAR
  /// (31) CTDP Level 1 PPC
  /// (32) CTDP Level 2 Power Limit1
  /// (34) CTDP Level 2 Power Limit2
  /// (36) CTDP Level 2 Power Limit1 Time Window
  /// (37) CTDP Level 2 CTC
  /// (38) CTDP Level 2 TAR
  /// (39) CTDP Level 2 PPC
  ///
  PPM_CTDP_LEVEL_SETTINGS CtdpLevelSettings[3];
  //
  // Mwait Hints and Latency values for C3/C6/C7/C7S
  //
  UINT8  C3MwaitValue;             ///< (40) Mwait Hint value for C3
  UINT8  C6MwaitValue;             ///< (41) Mwait Hint value for C6
  UINT8  C7MwaitValue;             ///< (42) Mwait Hint value for C6
  UINT8  CDMwaitValue;             ///< (43) Mwait Hint value for C7/C8/C9/C10
  UINT16 C3Latency;                ///< (44-45) Latency value for C3
  UINT16 C6Latency;                ///< (46-47) Latency Value for C6
  UINT16 C7Latency;                ///< (48-49) Latency Value for C6
  UINT16 CDLatency;                ///< (50-51) Latency Value for C7/C8/C9/C10
  UINT16 CDIOLevel;                ///< (52-53) IO Level Value for C7/C8/C9/C10
  UINT16 CDPowerValue;             ///< (54-55) Power Value for C7/C8/C9/C10
  UINT8  MiscPowerManagementFlags; ///< (55) MiscPowerManagementFlags
  //
  // DTS
  //
  UINT8  EnableDigitalThermalSensor;           ///< (57) DTS Function enable
  UINT8  BspDigitalThermalSensorTemperature;   ///< (58) Temperature of BSP
  UINT8  ApDigitalThermalSensorTemperature;    ///< (59) Temperature of AP
  UINT8  DigitalThermalSensorSmiFunction;      ///< (60) SMI function call via DTS IO Trap
  UINT8  PackageDTSTemperature;                ///< (61) Package temperature
  UINT8  IsPackageTempMSRAvailable;            ///< (62) Package Temperature MSR available
  UINT8  Ap2DigitalThermalSensorTemperature;   ///< (63) Temperature of the second AP
  UINT8  Ap3DigitalThermalSensorTemperature;   ///< (64) Temperature of the third AP
  //
  // BIOS Guard
  //
  UINT64 BiosGuardMemAddress;                  ///< (65-72) BIOS Guard Memory Address for Tool Interface
  UINT8  BiosGuardMemSize;                     ///< (73) BIOS Guard Memory Size for Tool Interface
  UINT16 BiosGuardIoTrapAddress;               ///< (74-75) IoTrap Address for Tool Interface
  UINT16 BiosGuardIoTrapLength;                ///< (76-77) IoTrap Length for Tool Interface
  //
  // DTS I/O Trap
  //
  UINT16 DtsIoTrapAddress;                     ///< (78-79) DTS IO trap Address
  UINT8  DtsIoTrapLength;                      ///< (80)    DTS IO trap Length
  UINT8  DtsAcpiEnable;                        ///< (81) DTS is in ACPI Mode Enabled

  //
  // Software Guard Extension
  //
  UINT8  SgxStatus;                            ///< (82)    SE Status
  UINT64 EpcBaseAddress;                       ///< (83-90) EPC Base Address
  UINT64 EpcLength;                            ///< (91-98) EPC Length

  //
  //  HWP
  //
  UINT8  HwpVersion;                           ///< (99) HWP Status
  UINT16 HwpIoTrapAddress;                     ///< (100-101) IoTrap Address for HWP
  UINT16 HwpIoTrapLength;                      ///< (102-103) IoTrap Length for HWP

  UINT8  PowerState;                           ///< (104) Power State
  UINT8  EnableHdcPolicy;                      ///< (105) Hardware Duty Cycling Policy

  UINT8  HwpInterruptStatus;                   ///< (106) HWP Interrupt Status
  UINT8  DtsInterruptStatus;                   ///< (107) DTS Interrupt Status
} CPU_GLOBAL_NVS_AREA;
#pragma pack()
///
/// CPU Global NVS Area Protocol
///
struct _CPU_GLOBAL_NVS_AREA_PROTOCOL {
  CPU_GLOBAL_NVS_AREA *Area;                   ///< CPU NVS Area
};


typedef VOID* (EFIAPI *EFI_SMBIOS_GET_TABLE_ENTRY) (
);

typedef VOID* (EFIAPI *EFI_SMBIOS_GET_SCRATCH_BUFFER) (
);

typedef UINT16 (EFIAPI *EFI_SMBIOS_GET_BUFFER_MAX_SIZE) (
);

typedef UINT16 (EFIAPI *EFI_SMBIOS_GET_FREE_HANDLE) (
);

typedef EFI_STATUS (EFIAPI *EFI_SMBIOS_ADD_STRUCTURE) (
    IN UINT8        *Buffer,
    IN UINT16       Size
);

typedef EFI_STATUS (EFIAPI *EFI_SMBIOS_ADD_STRUC_HANDLE) (
    IN UINT16       Handle,
    IN UINT8        *Buffer,
    IN UINT16       Size
);

typedef EFI_STATUS (EFIAPI *EFI_SMBIOS_DELETE_STRUCTURE) (
    IN UINT16       Handle
);

typedef EFI_STATUS (EFIAPI *EFI_SMBIOS_READ_STRUCTURE) (
    IN      UINT16  Handle,
    IN OUT  UINT8   **BufferPtr,
    IN OUT  UINT16  *BufferSize
);

typedef EFI_STATUS (EFIAPI *EFI_SMBIOS_READ_STRUC_TYPE) (
    IN UINT8        Type,
    IN UINT8        Instance,
    IN UINT8        **BufferPtr,
    IN UINT16       *BufferSize
);

typedef EFI_STATUS (EFIAPI *EFI_SMBIOS_WRITE_STRUCTURE) (
    IN UINT16       Handle,
    IN UINT8        *BufferPtr,
    IN UINT16       BufferSize
);

typedef EFI_STATUS (EFIAPI *EFI_SMBIOS_ADD_STRUC_INDEX) (
    IN UINT16       Handle,
    IN UINT8        *Buffer,
    IN UINT16       Size,
    IN UINT16       Index
);

typedef EFI_STATUS (EFIAPI *EFI_SMBIOS_UPDATE_HEADER) (
);

typedef VOID* (EFIAPI *EFI_SMBIOS_GET_VER_TABLE_ENTRY) (
    IN UINT8                  SmbiosMajorVersion
);

typedef struct {
    EFI_SMBIOS_GET_TABLE_ENTRY      SmbiosGetTableEntryPoint;   // Get SMBIOS V2 Table Entry Point
    EFI_SMBIOS_GET_SCRATCH_BUFFER   SmbiosGetScratchBufferPtr;  // Scratch Buffer of maximum table size
    EFI_SMBIOS_GET_BUFFER_MAX_SIZE  SmbiosGetBufferMaxSize;     // Maximum SMBIOS Table Size
    EFI_SMBIOS_GET_FREE_HANDLE      SmbiosGetFreeHandle;        // Get available free handle
    EFI_SMBIOS_ADD_STRUCTURE        SmbiosAddStructure;         // Add structure
    EFI_SMBIOS_ADD_STRUC_HANDLE     SmbiosAddStrucByHandle;     // Add structure (by handle)
    EFI_SMBIOS_DELETE_STRUCTURE     SmbiosDeleteStructure;      // Delete structure (by handle)
    EFI_SMBIOS_READ_STRUCTURE       SmbiosReadStructure;        // Read structure. Caller is responsible
                                                                // for deallocating the memory
    EFI_SMBIOS_READ_STRUC_TYPE      SmbiosReadStrucByType;      // Read structure by type. Caller is
                                                                // responsible for deallocating the memory
    EFI_SMBIOS_WRITE_STRUCTURE      SmbiosWriteStructure;       // Write structure
    EFI_SMBIOS_UPDATE_HEADER        SmbiosUpdateHeader;         // Update SMBIOS Table Header
    EFI_SMBIOS_ADD_STRUC_INDEX      SmbiosAddStrucByIndex;      // Add structure
    EFI_SMBIOS_GET_VER_TABLE_ENTRY  SmbiosGetVerTableEntryPoint;// Get input version of SMBIOS Table Entry Point
} AMI_SMBIOS_PROTOCOL;

typedef struct {
  EFI_STATUS (EFIAPI *UNKNOWN_FUNC1)(VOID);
}AMI_SMBIOS_FLASH_DATA_PROTOCOL;


VOID InstallSmmFuzzProtocol();
VOID HookGBS (VOID);
extern GUID gSmmFuzzHobGuid;
extern GUID gSmmFuzzDataProtocolGuid;
extern GUID gPchNvsAreaProtocolGuid;
extern GUID gSaPolicyProtocolGuid;
extern GUID gDxeCpuPolicyProtocolGuid;
extern GUID gEfiAcpiSupportProtocolGuid;
extern GUID gPowerMgmtInitDoneProtocolGuid;
extern GUID gPlatformNvsAreaProtocolGuid;
extern GUID gUnknownHpProtocol1Guid;
extern GUID gUnknownHpProtocol2Guid;
extern GUID gAmiSmbiosProtocolGuid;
extern GUID gUnknownHpProtocol4Guid;
extern GUID gCpuNvsAreaProtocolGuid;
extern GUID gCpuGlobalNvsAreaProtocolGuid;
extern GUID GAmiSmbiosFlashDataProtocolGuid;
#endif
