// Copyright Root Herald. Apache-2.0.

#include "RootHeraldClient.h"
#include "HAL/PlatformProcess.h"
#include "Interfaces/IPluginManager.h"
#include "Misc/Paths.h"

#ifndef ROOTHERALD_DLL_NAME
#define ROOTHERALD_DLL_NAME TEXT("RootHerald")
#endif

// ---------------------------------------------------------------------------
// Mirror of the public C ABI from src/clients/common/rootherald.h. We declare
// the function-pointer types locally instead of #including the header so the
// plugin compiles without the header on the include path.
// ---------------------------------------------------------------------------

extern "C"
{
    typedef struct RootHeraldClient RootHeraldClient_t;
    typedef enum {
        RH_PROTO_OK = 0,
        ROOTHERALD_ERR_INVALID_ARG = 1,
        ROOTHERALD_ERR_TPM_UNAVAILABLE = 2,
        RH_PROTO_ERR_NETWORK = 3,
        ROOTHERALD_ERR_SERVER = 4,
        ROOTHERALD_ERR_QUOTA_EXCEEDED = 5,
        RH_PROTO_ERR_INTERNAL = 99
    } RootHeraldStatus_t;

    typedef enum {
        ROOTHERALD_VERDICT_ALLOW = 0,
        ROOTHERALD_VERDICT_WARN = 1,
        ROOTHERALD_VERDICT_DENY = 2
    } RootHeraldVerdict_t;

    struct RootHeraldVerifyResult_t
    {
        RootHeraldVerdict_t Verdict;
        char DeviceId[129];
        char TpmClass[64];
        char PostureJson[1024];
        char Reason[256];
    };

    typedef RootHeraldClient_t* (*Pfn_Create)(const char*, const char*);
    typedef void                (*Pfn_Destroy)(RootHeraldClient_t*);
    typedef RootHeraldStatus_t  (*Pfn_Verify)(RootHeraldClient_t*, const char*, RootHeraldVerifyResult_t*);
    typedef const char*         (*Pfn_AbiVer)(void);
    typedef const char*         (*Pfn_LibVer)(void);
}

void* URootHeraldClient::DllHandle = nullptr;

static Pfn_Create  GCreate  = nullptr;
static Pfn_Destroy GDestroy = nullptr;
static Pfn_Verify  GVerify  = nullptr;
static Pfn_AbiVer  GAbiVer  = nullptr;
static Pfn_LibVer  GLibVer  = nullptr;

bool URootHeraldClient::EnsureDllLoaded()
{
    if (DllHandle != nullptr) return true;

    // Resolve the native binary that the .Build.cs staged into Binaries/.
    FString PluginDir = IPluginManager::Get().FindPlugin(TEXT("RootHeraldUE"))->GetBaseDir();
#if PLATFORM_WINDOWS
    FString DllPath = FPaths::Combine(PluginDir, TEXT("Binaries"), TEXT("Win64"), ROOTHERALD_DLL_NAME);
#elif PLATFORM_MAC
    FString DllPath = FPaths::Combine(PluginDir, TEXT("Binaries"), TEXT("Mac"), TEXT("RootHeraldKit.framework/RootHeraldKit"));
#elif PLATFORM_LINUX
    FString DllPath = FPaths::Combine(PluginDir, TEXT("Binaries"), TEXT("Linux"), ROOTHERALD_DLL_NAME);
#else
    FString DllPath;
#endif

    DllHandle = FPlatformProcess::GetDllHandle(*DllPath);
    if (!DllHandle)
    {
        UE_LOG(LogTemp, Warning, TEXT("RootHeraldUE: failed to load %s"), *DllPath);
        return false;
    }

    GCreate  = (Pfn_Create) FPlatformProcess::GetDllExport(DllHandle, TEXT("RootHeraldClient_Create"));
    GDestroy = (Pfn_Destroy)FPlatformProcess::GetDllExport(DllHandle, TEXT("RootHeraldClient_Destroy"));
    GVerify  = (Pfn_Verify) FPlatformProcess::GetDllExport(DllHandle, TEXT("RootHeraldClient_Verify"));
    GAbiVer  = (Pfn_AbiVer) FPlatformProcess::GetDllExport(DllHandle, TEXT("RootHerald_AbiVersionString"));
    GLibVer  = (Pfn_LibVer) FPlatformProcess::GetDllExport(DllHandle, TEXT("RootHerald_LibraryVersionString"));
    return GCreate && GDestroy && GVerify;
}

URootHeraldClient::URootHeraldClient() {}
URootHeraldClient::~URootHeraldClient()
{
    if (NativeHandle && GDestroy)
    {
        GDestroy(reinterpret_cast<RootHeraldClient_t*>(NativeHandle));
        NativeHandle = nullptr;
    }
}

bool URootHeraldClient::Initialize(const FString& ApiKey, const FString& Endpoint)
{
    if (!EnsureDllLoaded()) return false;
    auto KeyUtf8 = StringCast<ANSICHAR>(*ApiKey);
    auto EpUtf8  = StringCast<ANSICHAR>(*Endpoint);
    NativeHandle = GCreate(KeyUtf8.Get(), EpUtf8.Get());
    return NativeHandle != nullptr;
}

FRootHeraldVerifyResult URootHeraldClient::Verify(const FString& Action)
{
    FRootHeraldVerifyResult Out;
    if (!NativeHandle || !GVerify)
    {
        Out.Reason = TEXT("Root Herald not initialized");
        return Out;
    }
    RootHeraldVerifyResult_t Native = {};
    auto ActionUtf8 = StringCast<ANSICHAR>(*Action);
    RootHeraldStatus_t Status = GVerify(
        reinterpret_cast<RootHeraldClient_t*>(NativeHandle),
        ActionUtf8.Get(),
        &Native);

    Out.Verdict = static_cast<ERootHeraldVerdict>(Native.Verdict);
    Out.DeviceId = FString(ANSI_TO_TCHAR(Native.DeviceId));
    Out.TpmClass = FString(ANSI_TO_TCHAR(Native.TpmClass));
    Out.PostureJson = FString(ANSI_TO_TCHAR(Native.PostureJson));
    Out.Reason = (Status == RH_PROTO_OK)
        ? FString(ANSI_TO_TCHAR(Native.Reason))
        : FString::Printf(TEXT("verify failed (%d)"), (int32)Status);
    return Out;
}

FString URootHeraldClient::GetAbiVersion()
{
    if (!EnsureDllLoaded() || !GAbiVer) return TEXT("unknown");
    const char* P = GAbiVer();
    return P ? FString(ANSI_TO_TCHAR(P)) : TEXT("unknown");
}

FString URootHeraldClient::GetLibraryVersion()
{
    if (!EnsureDllLoaded() || !GLibVer) return TEXT("unknown");
    const char* P = GLibVer();
    return P ? FString(ANSI_TO_TCHAR(P)) : TEXT("unknown");
}
