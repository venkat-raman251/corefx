// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.InteropServices;

internal partial class Interop
{
    internal partial class mincore
    {
        internal unsafe partial struct InlineArray_LUID_AND_ATTRIBUTES_1
        {
            public LUID_AND_ATTRIBUTES this[uint index]
            {
                get
                {
                    if (index < 0
                                || index >= 1)
                        throw new global::System.IndexOutOfRangeException();
                    fixed (InlineArray_LUID_AND_ATTRIBUTES_1* pThis = &(this))
                        return ((LUID_AND_ATTRIBUTES*)pThis)[index];
                }
                set
                {
                    if (index < 0
                                || index >= 1)
                        throw new global::System.IndexOutOfRangeException();
                    fixed (InlineArray_LUID_AND_ATTRIBUTES_1* pThis = &(this))
                        ((LUID_AND_ATTRIBUTES*)pThis)[index] = value;
                }
            }
            public const int Length = 1; LUID_AND_ATTRIBUTES elem_0;
        }
    }
}
