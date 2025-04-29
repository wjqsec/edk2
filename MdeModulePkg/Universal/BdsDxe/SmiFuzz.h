#include "../../Core/PiSmmCore/PiSmmCore.h"
#include "../../Core/Dxe/DxeMain/SmmFuzzProtocol.h"
SMM_MODULE_HANDLER_PROTOCOL_INFO ** CollectModuleDependency(SMM_MODULES_HANDLER_PROTOCOL_INFO *Info, SMM_MODULE_HANDLER_PROTOCOL_INFO *Module, UINTN *NumDep);
EFI_STATUS
EFIAPI
SmmFuzzMain(
    IN EFI_HANDLE ImageHandle,
    IN EFI_SYSTEM_TABLE *SystemTable);
extern GUID gSmmFuzzDxeModuleInfoProtocolGuid;
    