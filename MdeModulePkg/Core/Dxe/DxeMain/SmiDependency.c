#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Protocol/SmmCommunication.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Core/PiSmmCore/PiSmmCore.h>
#include <Guid/MemoryProfile.h>
#include <Guid/PiSmmCommunicationRegionTable.h>
#include <Guid/GlobalVariable.h>
#include <Protocol/Cpu.h>
#include <Uefi/UefiBaseType.h>
#include <Uefi.h>
#include <Library/PrintLib.h>
#include <Guid/DxeServices.h>
#include <Base.h>
#include <Uefi.h>
#include <Library/PeCoffGetEntryPointLib.h>
#include <Library/SerialPortLib.h>
#include <Library/SynchronizationLib.h>
#include <Library/PrintLib.h>
#include <Protocol/SmmBase2.h>
#include <Register/Intel/Cpuid.h>
#include <Register/Intel/Msr.h>
#include "PiDxe.h"
#include <Guid/EventGroup.h>
#include <Protocol/FirmwareVolumeBlock.h>
#include <Protocol/DevicePath.h>
#include <Library/UefiDriverEntryPoint.h>
#include <Library/BaseLib.h>
#include <Library/DxeServicesTableLib.h>
#include <Library/UefiRuntimeLib.h>
#include <Library/HobLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/DevicePathLib.h>

#include "SmiFuzz.h"
static SMM_MODULE_HANDLER_PROTOCOL_INFO *FindProtocolProducer(SMM_MODULES_HANDLER_PROTOCOL_INFO *Info, GUID *Protocol) {
  for(UINTN i = 0; i < Info->NumModules ; i++) {
    for(UINTN j = 0; j < Info->info[i].NumProduceProtocols; j++) {
      if(CompareGuid(Protocol,&Info->info[i].ProduceProtocols[j]))
        return &Info->info[i];
    }
  }
  return NULL;
}

static BOOLEAN DepAlreadyCollected(SMM_MODULE_HANDLER_PROTOCOL_INFO **Dep, UINTN NumDep, SMM_MODULE_HANDLER_PROTOCOL_INFO *NewDep) {
  for (UINTN i = 0; i < NumDep ; i++) {
    if(Dep[i] == NewDep)
      return TRUE;
  }
  return FALSE;
}
SMM_MODULE_HANDLER_PROTOCOL_INFO ** CollectModuleDependency(SMM_MODULES_HANDLER_PROTOCOL_INFO *Info, SMM_MODULE_HANDLER_PROTOCOL_INFO *Module, UINTN *NumDep) 
{
  UINTN NumDepRet = 1;
  SMM_MODULE_HANDLER_PROTOCOL_INFO **Ret;
  Ret = AllocatePool(sizeof(SMM_MODULE_HANDLER_PROTOCOL_INFO *) * NumDepRet);
  Ret[NumDepRet - 1] = Module;
  

  while (TRUE) {
    UINTN NumDepTmp = NumDepRet;
    for (UINTN i = 0; i < NumDepRet ; i++) {
      for (UINTN j = 0; j < Ret[i]->NumConsumeProtocols; j++) {
        SMM_MODULE_HANDLER_PROTOCOL_INFO *Dep = FindProtocolProducer(Info, &Ret[i]->ConsumeProtocols[j]);
        if (Dep == NULL) {
          continue;
        } 
        if (DepAlreadyCollected(Ret,NumDepTmp,Dep))
          continue;
        
        // SMM_MODULE_HANDLER_PROTOCOL_INFO *TmpDependency = *Dependency;
        
        // *Dependency = AllocatePool(sizeof(SMM_MODULE_HANDLER_PROTOCOL_INFO *) * (NumDep + 1));
        // CopyMem(*Dependency, TmpDependency, sizeof(SMM_MODULE_HANDLER_PROTOCOL_INFO *) * NumDep);
        // FreePool(TmpDependency);
        Ret = ReallocatePool (sizeof(SMM_MODULE_HANDLER_PROTOCOL_INFO *) * NumDepTmp, sizeof(SMM_MODULE_HANDLER_PROTOCOL_INFO *) * ( NumDepTmp + 1 ), Ret);
        NumDepTmp++;
        Ret[NumDepTmp - 1] = Dep;
      }
    }
    if (NumDepTmp == NumDepRet)
      break;
    NumDepRet = NumDepTmp;
  }
  *NumDep = NumDepRet;
  return Ret;
}