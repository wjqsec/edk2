#define MAX_NUM_DXE_MODULES 100
typedef struct MODULE_INFO {
  GUID Guid;
  UINTN StartAddress;
  UINTN Size;
}MODULE_INFO;
typedef struct DXE_MODULE_INFOS {
  UINTN NumDxeModules;
  MODULE_INFO DxeModules[MAX_NUM_DXE_MODULES];
}DXE_MODULE_INFOS;