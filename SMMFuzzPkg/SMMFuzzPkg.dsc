[Defines]
  DSC_SPECIFICATION         = 0x00010005 # It is the version of the DSC specification that this file conforms to.
  PLATFORM_GUID             = c4d69391-7c20-426e-b1d4-33cbabc7116c # Create GUID - https://www.guidgenerator.com/online-guid-generator.aspx
  PLATFORM_VERSION          = 0.01 # The version of the platform.
  PLATFORM_NAME             = SMMFuzzPkg # The name of the platform.
  SKUID_IDENTIFIER          = DEFAULT # The contents of this section are used to define valid SKUID_IDENTIFIER names.
  SUPPORTED_ARCHITECTURES   = AARCH64|X64 # all supported architectures for this platform
  BUILD_TARGETS             = DEBUG|RELEASE|NOOPT 
  OUTPUT_DIRECTORY          = Build/SMMFuzzPkg

# Varios libs that are required to build the our UEFI application
[LibraryClasses]
  #
  # Basic
  #
  BaseLib|MdePkg/Library/BaseLib/BaseLib.inf
  BaseMemoryLib|MdePkg/Library/BaseMemoryLib/BaseMemoryLib.inf
  DevicePathLib|MdePkg/Library/UefiDevicePathLib/UefiDevicePathLib.inf
  MemoryAllocationLib|MdePkg/Library/UefiMemoryAllocationLib/UefiMemoryAllocationLib.inf
  PrintLib|MdePkg/Library/BasePrintLib/BasePrintLib.inf
  UefiLib|MdePkg/Library/UefiLib/UefiLib.inf

  #
  # UEFI & PI
  #
  UefiApplicationEntryPoint|MdePkg/Library/UefiApplicationEntryPoint/UefiApplicationEntryPoint.inf
  UefiBootServicesTableLib|MdePkg/Library/UefiBootServicesTableLib/UefiBootServicesTableLib.inf
  UefiRuntimeServicesTableLib|MdePkg/Library/UefiRuntimeServicesTableLib/UefiRuntimeServicesTableLib.inf

  #
  # Misc
  #
  DebugLib|MdePkg/Library/BaseDebugLibNull/BaseDebugLibNull.inf
  PcdLib|MdePkg/Library/BasePcdLibNull/BasePcdLibNull.inf
  RegisterFilterLib|MdePkg/Library/RegisterFilterLibNull/RegisterFilterLibNull.inf

[LibraryClasses.ARM,LibraryClasses.AARCH64]
  #
  # It is not possible to prevent the ARM compiler for generic intrinsic functions.
  # This library provides the instrinsic functions generate by a given compiler.
  # [LibraryClasses.ARM] and NULL mean link this library into all ARM images.
  #
  NULL|ArmPkg/Library/CompilerIntrinsicsLib/CompilerIntrinsicsLib.inf

  # Add support for GCC stack protector
  NULL|MdePkg/Library/BaseStackCheckLib/BaseStackCheckLib.inf

[Components]
  SMMFuzzPkg/SMMFuzzApplication.inf