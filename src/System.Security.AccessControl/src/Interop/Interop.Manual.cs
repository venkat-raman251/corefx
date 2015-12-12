// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

internal partial class Interop
{
    // Constants

    // Access Control library
    internal const string MICROSOFT_KERBEROS_NAME = "Kerberos";
    internal const uint ANONYMOUS_LOGON_LUID = 0x3e6;

    internal const int SECURITY_ANONYMOUS_LOGON_RID = 0x00000007;
    internal const int SECURITY_AUTHENTICATED_USER_RID = 0x0000000B;
    internal const int SECURITY_LOCAL_SYSTEM_RID = 0x00000012;
    internal const int SECURITY_BUILTIN_DOMAIN_RID = 0x00000020;

    internal const uint SE_PRIVILEGE_DISABLED = 0x00000000;
    internal const uint SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001;
    internal const uint SE_PRIVILEGE_ENABLED = 0x00000002;
    internal const uint SE_PRIVILEGE_USED_FOR_ACCESS = 0x80000000;

    internal const uint SE_GROUP_MANDATORY = 0x00000001;
    internal const uint SE_GROUP_ENABLED_BY_DEFAULT = 0x00000002;
    internal const uint SE_GROUP_ENABLED = 0x00000004;
    internal const uint SE_GROUP_OWNER = 0x00000008;
    internal const uint SE_GROUP_USE_FOR_DENY_ONLY = 0x00000010;
    internal const uint SE_GROUP_LOGON_ID = 0xC0000000;
    internal const uint SE_GROUP_RESOURCE = 0x20000000;

    internal const uint DUPLICATE_CLOSE_SOURCE = 0x00000001;
    internal const uint DUPLICATE_SAME_ACCESS = 0x00000002;
    internal const uint DUPLICATE_SAME_ATTRIBUTES = 0x00000004;

    internal const int ERROR_SUCCESS = 0x0;
    internal const int ERROR_INVALID_FUNCTION = 0x1;
    internal const int ERROR_FILE_NOT_FOUND = 0x2;
    internal const int ERROR_PATH_NOT_FOUND = 0x3;
    internal const int ERROR_ACCESS_DENIED = 0x5;
    internal const int ERROR_INVALID_HANDLE = 0x6;
    internal const int ERROR_NOT_ENOUGH_MEMORY = 0x8;
    internal const int ERROR_INVALID_DATA = 0xd;
    internal const int ERROR_INVALID_DRIVE = 0xf;
    internal const int ERROR_NO_MORE_FILES = 0x12;
    internal const int ERROR_NOT_READY = 0x15;
    internal const int ERROR_BAD_LENGTH = 0x18;
    internal const int ERROR_SHARING_VIOLATION = 0x20;
    internal const int ERROR_NOT_SUPPORTED = 0x32;
    internal const int ERROR_FILE_EXISTS = 0x50;
    internal const int ERROR_INVALID_PARAMETER = 0x57;
    internal const int ERROR_BROKEN_PIPE = 0x6D;
    internal const int ERROR_CALL_NOT_IMPLEMENTED = 0x78;
    internal const int ERROR_INSUFFICIENT_BUFFER = 0x7A;
    internal const int ERROR_INVALID_NAME = 0x7B;
    internal const int ERROR_BAD_PATHNAME = 0xA1;
    internal const int ERROR_ALREADY_EXISTS = 0xB7;
    internal const int ERROR_ENVVAR_NOT_FOUND = 0xCB;
    internal const int ERROR_FILENAME_EXCED_RANGE = 0xCE;  // filename too long.
    internal const int ERROR_NO_DATA = 0xE8;
    internal const int ERROR_PIPE_NOT_CONNECTED = 0xE9;
    internal const int ERROR_MORE_DATA = 0xEA;
    internal const int ERROR_DIRECTORY = 0x10B;
    internal const int ERROR_OPERATION_ABORTED = 0x3E3;  // 995; For IO Cancellation
    internal const int ERROR_NOT_FOUND = 0x490;          // 1168; For IO Cancellation
    internal const int ERROR_NO_TOKEN = 0x3f0;
    internal const int ERROR_DLL_INIT_FAILED = 0x45A;
    internal const int ERROR_NON_ACCOUNT_SID = 0x4E9;
    internal const int ERROR_NOT_ALL_ASSIGNED = 0x514;
    internal const int ERROR_UNKNOWN_REVISION = 0x519;
    internal const int ERROR_INVALID_OWNER = 0x51B;
    internal const int ERROR_INVALID_PRIMARY_GROUP = 0x51C;
    internal const int ERROR_NO_SUCH_PRIVILEGE = 0x521;
    internal const int ERROR_PRIVILEGE_NOT_HELD = 0x522;
    internal const int ERROR_NONE_MAPPED = 0x534;
    internal const int ERROR_INVALID_ACL = 0x538;
    internal const int ERROR_INVALID_SID = 0x539;
    internal const int ERROR_INVALID_SECURITY_DESCR = 0x53A;
    internal const int ERROR_BAD_IMPERSONATION_LEVEL = 0x542;
    internal const int ERROR_CANT_OPEN_ANONYMOUS = 0x543;
    internal const int ERROR_NO_SECURITY_ON_OBJECT = 0x546;
    internal const int ERROR_TRUSTED_RELATIONSHIP_FAILURE = 0x6FD;

    // Error codes from ntstatus.h
    internal const uint STATUS_SUCCESS = 0x00000000;
    internal const uint STATUS_SOME_NOT_MAPPED = 0x00000107;
    internal const uint STATUS_NO_MEMORY = 0xC0000017;
    internal const uint STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034;
    internal const uint STATUS_NONE_MAPPED = 0xC0000073;
    internal const uint STATUS_INSUFFICIENT_RESOURCES = 0xC000009A;
    internal const uint STATUS_ACCESS_DENIED = 0xC0000022;

    internal static partial class mincore
    {
        // PInvokes

        [DllImport("api-ms-win-core-handle-l1-1-0", SetLastError = true)]
        internal static extern bool CloseHandle(IntPtr handle);

        [DllImport("api-ms-win-core-heap-obsolete-l1-1-0", SetLastError = true)]
        internal static extern IntPtr LocalFree(IntPtr handle);

        [DllImport("api-ms-win-security-base-l1-1-0", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern
        bool AdjustTokenPrivileges(
            [In]     SafeTokenHandle TokenHandle,
            [In]     bool DisableAllPrivileges,
            [In]     ref TOKEN_PRIVILEGE NewState,
            [In]     uint BufferLength,
            [In, Out] ref TOKEN_PRIVILEGE PreviousState,
            [In, Out] ref uint ReturnLength);

        [DllImport(
             "api-ms-win-security-sddl-l1-1-0",
             EntryPoint = "ConvertSecurityDescriptorToStringSecurityDescriptorW",
             CallingConvention = CallingConvention.Winapi,
             SetLastError = true,
             ExactSpelling = true,
             CharSet = CharSet.Unicode)]
        internal static extern int ConvertSdToStringSd(
            byte[] securityDescriptor,
            /* DWORD */ uint requestedRevision,
            uint securityInformation,
            out IntPtr resultString,
            ref uint resultStringLength);

        [DllImport(
             "api-ms-win-security-sddl-l1-1-0",
             EntryPoint = "ConvertStringSecurityDescriptorToSecurityDescriptorW",
             CallingConvention = CallingConvention.Winapi,
             SetLastError = true,
             ExactSpelling = true,
             CharSet = CharSet.Unicode)]
        internal static extern int ConvertStringSdToSd(
            string stringSd,
            /* DWORD */ uint stringSdRevision,
            out IntPtr resultSd,
            ref uint resultSdLength);

        [DllImport(
            "api-ms-win-security-lsalookup-l2-1-0",
            EntryPoint = "LookupPrivilegeValueW",
            CharSet = CharSet.Unicode,
            SetLastError = true,
            ExactSpelling = true,
            BestFitMapping = false)]
        internal static extern
        bool LookupPrivilegeValue(
            [In]     string lpSystemName,
            [In]     string lpName,
            [In, Out] ref LUID Luid);

        [DllImport(
             "api-ms-win-security-base-l1-1-0",
             EntryPoint = "GetSecurityDescriptorLength",
             CallingConvention = CallingConvention.Winapi,
             SetLastError = true,
             ExactSpelling = true,
             CharSet = CharSet.Unicode)]
        internal static extern /*DWORD*/ uint GetSecurityDescriptorLength(
            IntPtr byteArray);

        [DllImport(
             "api-ms-win-security-provider-l1-1-0",
             EntryPoint = "GetSecurityInfo",
             CallingConvention = CallingConvention.Winapi,
             SetLastError = true,
             ExactSpelling = true,
             CharSet = CharSet.Unicode)]
        internal static extern /*DWORD*/ uint GetSecurityInfoByHandle(
            SafeHandle handle,
            /*DWORD*/ uint objectType,
            /*DWORD*/ uint securityInformation,
            out IntPtr sidOwner,
            out IntPtr sidGroup,
            out IntPtr dacl,
            out IntPtr sacl,
            out IntPtr securityDescriptor);

        [DllImport(
             "api-ms-win-security-provider-l1-1-0",
             EntryPoint = "GetNamedSecurityInfoW",
             CallingConvention = CallingConvention.Winapi,
             SetLastError = true,
             ExactSpelling = true,
             CharSet = CharSet.Unicode)]
        internal static extern /*DWORD*/ uint GetSecurityInfoByName(
            string name,
            /*DWORD*/ uint objectType,
            /*DWORD*/ uint securityInformation,
            out IntPtr sidOwner,
            out IntPtr sidGroup,
            out IntPtr dacl,
            out IntPtr sacl,
            out IntPtr securityDescriptor);

        [DllImport(
             "api-ms-win-security-provider-l1-1-0",
             EntryPoint = "SetNamedSecurityInfoW",
             CallingConvention = CallingConvention.Winapi,
             SetLastError = true,
             ExactSpelling = true,
             CharSet = CharSet.Unicode)]
        internal static extern /*DWORD*/ uint SetSecurityInfoByName(
            string name,
            /*DWORD*/ uint objectType,
            /*DWORD*/ uint securityInformation,
            byte[] owner,
            byte[] group,
            byte[] dacl,
            byte[] sacl);

        [DllImport(
             "api-ms-win-security-provider-l1-1-0",
             EntryPoint = "SetSecurityInfo",
             CallingConvention = CallingConvention.Winapi,
             SetLastError = true,
             ExactSpelling = true,
             CharSet = CharSet.Unicode)]
        internal static extern /*DWORD*/ uint SetSecurityInfoByHandle(
            SafeHandle handle,
            /*DWORD*/ uint objectType,
            /*DWORD*/ uint securityInformation,
            byte[] owner,
            byte[] group,
            byte[] dacl,
            byte[] sacl);

        [DllImport("api-ms-win-security-base-l1-1-0", SetLastError = true)]
        internal static extern
        bool DuplicateTokenEx(
            [In]     SafeTokenHandle ExistingTokenHandle,
            [In]     TokenAccessLevels DesiredAccess,
            [In]     IntPtr TokenAttributes,
            [In]     SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
            [In]     System.Security.Principal.TokenType TokenType,
            [In, Out] ref SafeTokenHandle DuplicateTokenHandle);

        [DllImport("api-ms-win-core-processthreads-l1-1-0", SetLastError = true)]
        internal static extern IntPtr GetCurrentProcess();

        [DllImport("api-ms-win-core-processthreads-l1-1-0", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern
        bool OpenProcessToken(
            [In]     IntPtr ProcessToken,
            [In]     TokenAccessLevels DesiredAccess,
            [Out]    out SafeTokenHandle TokenHandle);

        [System.Security.SecurityCritical]
        [DllImport("api-ms-win-core-processthreads-l1-1-0", SetLastError = true)]
        internal static extern bool OpenThreadToken(IntPtr ThreadHandle, TokenAccessLevels dwDesiredAccess, bool bOpenAsSelf, out SafeTokenHandle phThreadToken);

        [System.Security.SecurityCritical]
        [DllImport("api-ms-win-security-base-l1-1-0", SetLastError = true)]
        internal static extern int ImpersonateLoggedOnUser(SafeTokenHandle hToken);

        [System.Security.SecurityCritical]
        [DllImport("api-ms-win-security-base-l1-1-0", SetLastError = true)]
        internal static extern int RevertToSelf();

        [System.Security.SecurityCritical]
        [DllImport("api-ms-win-core-processthreads-l1-1-0", SetLastError = true)]
        internal static extern bool SetThreadToken(IntPtr ThreadHandle, SafeTokenHandle hToken);
    }
}




