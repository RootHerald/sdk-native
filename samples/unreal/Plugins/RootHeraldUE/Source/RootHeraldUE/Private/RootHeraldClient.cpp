// Copyright Root Herald. Apache-2.0.

#include "RootHeraldClient.h"
#include "HAL/PlatformProcess.h"
#include "Interfaces/IPluginManager.h"
#include "Misc/Paths.h"

#ifndef ROOTHERALD_DLL_NAME
#define ROOTHERALD_DLL_NAME TEXT("RootHerald")
#endif

// ---------------------------------------------------------------------------
// Mirror of the public C ABI from common/rootherald.h (ABI 3.0 — keyless). We
// declare the function-pointer types locally instead of #including the header so
// the plugin compiles without the header on the include path.
// ---------------------------------------------------------------------------

extern "C"
{
    typedef struct RootHeraldClient RootHeraldClient_t;
    typedef enum {
        ROOTHERALD_OK = 0,
        ROOTHERALD_ERR_INVALID_ARG = 1,
        ROOTHERALD_ERR_TPM_UNAVAILABLE = 2,
        ROOTHERALD_ERR_NETWORK = 3,
        ROOTHERALD_ERR_SERVER = 4,
        ROOTHERALD_ERR_QUOTA_EXCEEDED = 5,
        ROOTHERALD_ERR_NOT_ENROLLED = 6,
        ROOTHERALD_ERR_ELEVATION_REQUIRED = 7,
        ROOTHERALD_ERR_INTERNAL = 99
    } RootHeraldStatus_t;

    typedef RootHeraldClient_t* (*Pfn_Create)(void);
    typedef void                (*Pfn_Destroy)(RootHeraldClient_t*);
    typedef RootHeraldStatus_t  (*Pfn_Collect)(const char*, char**);
    typedef void                (*Pfn_Free)(char*);
    typedef const char*         (*Pfn_AbiVer)(void);
    typedef const char*         (*Pfn_LibVer)(void);
}

void* URootHeraldClient::DllHandle = nullptr;

static Pfn_Create  GCreate  = nullptr;
static Pfn_Destroy GDestroy = nullptr;
static Pfn_Collect GCollect = nullptr;
static Pfn_Free    GFree    = nullptr;
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
    GCollect = (Pfn_Collect)FPlatformProcess::GetDllExport(DllHandle, TEXT("RootHeraldClient_CollectEvidence"));
    GFree    = (Pfn_Free)   FPlatformProcess::GetDllExport(DllHandle, TEXT("RootHeraldClient_FreeEvidence"));
    GAbiVer  = (Pfn_AbiVer) FPlatformProcess::GetDllExport(DllHandle, TEXT("RootHerald_AbiVersionString"));
    GLibVer  = (Pfn_LibVer) FPlatformProcess::GetDllExport(DllHandle, TEXT("RootHerald_LibraryVersionString"));
    return GCreate && GDestroy && GCollect && GFree;
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

bool URootHeraldClient::Initialize()
{
    if (!EnsureDllLoaded()) return false;
    NativeHandle = GCreate();
    return NativeHandle != nullptr;
}

FString URootHeraldClient::CollectEvidence(const FString& NonceB64)
{
    if (!EnsureDllLoaded() || !GCollect || !GFree)
    {
        return FString();
    }
    auto NonceUtf8 = StringCast<ANSICHAR>(*NonceB64);
    char* Blob = nullptr;
    // CollectEvidence is handle-less (keyless): it takes only the nonce.
    RootHeraldStatus_t Status = GCollect(NonceUtf8.Get(), &Blob);
    if (Status != ROOTHERALD_OK || Blob == nullptr)
    {
        if (Blob) GFree(Blob);
        return FString();
    }
    FString Out = FString(ANSI_TO_TCHAR(Blob));
    GFree(Blob);
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
