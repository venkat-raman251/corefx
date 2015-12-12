//
// Set some #defines to pull in the correct set of definitions.
//
#define RPC_USE_NATIVE_WCHAR
#define UNICODE
//
// Include the headers that declare the functions referenced below
//
#include <windows.h>

BEGIN_MCG_DIRECTIVES
{
    IMPORT_TYPE(SECURITY_IMPERSONATION_LEVEL, internal, "Interop",    "SECURITY_IMPERSONATION_LEVEL")
    IMPORT_TYPE(TOKEN_PRIVILEGES,             internal, "Interop",    "TOKEN_PRIVILEGE")
    IMPORT_TYPE(LUID_AND_ATTRIBUTES,          internal, "Interop",    "LUID_AND_ATTRIBUTES")
    IMPORT_TYPE(LUID,                         internal, "Interop",    "LUID")
}
END_MCG_DIRECTIVES
