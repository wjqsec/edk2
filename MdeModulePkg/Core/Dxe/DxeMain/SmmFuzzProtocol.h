#define MAX_NUM_DXE_MODULES 300
typedef struct MODULE_INFO {
  GUID Guid;
  UINTN StartAddress;
  UINTN Size;
}MODULE_INFO;
typedef struct DXE_MODULE_INFOS {
  UINTN NumDxeModules;
  MODULE_INFO DxeModules[MAX_NUM_DXE_MODULES];
  UINTN NumSmmModules;
  MODULE_INFO SmmModules[MAX_NUM_DXE_MODULES];
}DXE_SMM_MODULE_INFOS;