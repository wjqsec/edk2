/** @file
  Defines the stack cookie variable for GCC and Clang compilers.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>

VOID  *__stack_chk_guard = (VOID *)(UINTN)0x0;

/**
  This function gets called when a gcc/clang generated stack cookie fails. This implementation does nothing when
  a stack cookie failure occurs.

**/
VOID
EFIAPI
__stack_chk_fail (
  VOID
  )
{
  volatile int a = 0;
  volatile int b = 0;
  volatile int c = a / b;
  (VOID)c;
}
