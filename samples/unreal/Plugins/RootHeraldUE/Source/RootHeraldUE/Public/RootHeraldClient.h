// Copyright Root Herald. Apache-2.0.

#pragma once

#include "CoreMinimal.h"
#include "UObject/NoExportTypes.h"
#include "RootHeraldClient.generated.h"

UENUM(BlueprintType)
enum class ERootHeraldVerdict : uint8
{
    Allow UMETA(DisplayName = "Allow"),
    Warn  UMETA(DisplayName = "Warn"),
    Deny  UMETA(DisplayName = "Deny"),
};

USTRUCT(BlueprintType)
struct FRootHeraldVerifyResult
{
    GENERATED_BODY()

    UPROPERTY(BlueprintReadOnly, Category = "Root Herald")
    ERootHeraldVerdict Verdict = ERootHeraldVerdict::Deny;

    UPROPERTY(BlueprintReadOnly, Category = "Root Herald")
    FString DeviceId;

    UPROPERTY(BlueprintReadOnly, Category = "Root Herald")
    FString TpmClass;

    UPROPERTY(BlueprintReadOnly, Category = "Root Herald")
    FString PostureJson;

    UPROPERTY(BlueprintReadOnly, Category = "Root Herald")
    FString Reason;
};

/**
 * Blueprint-callable Root Herald client.
 *
 * Mirrors the C ABI in src/clients/common/rootherald.h:
 *   Initialize → RootHeraldClient_Create
 *   Verify     → RootHeraldClient_Verify
 *
 * Dynamically loads RootHerald.dll / RootHeraldKit.framework / librootherald.so
 * via FPlatformProcess::GetDllHandle so the editor build is not bound to the
 * native artifact's presence at link time.
 */
UCLASS(BlueprintType)
class ROOTHERALDUE_API URootHeraldClient : public UObject
{
    GENERATED_BODY()

public:
    URootHeraldClient();
    virtual ~URootHeraldClient();

    /** Load the native library and create the underlying client handle. */
    UFUNCTION(BlueprintCallable, Category = "Root Herald")
    bool Initialize(const FString& ApiKey, const FString& Endpoint);

    /** Synchronous verify; pair with Async Task in BP for non-blocking calls. */
    UFUNCTION(BlueprintCallable, Category = "Root Herald")
    FRootHeraldVerifyResult Verify(const FString& Action);

    /** Library / ABI versions for diagnostic UI. */
    UFUNCTION(BlueprintCallable, Category = "Root Herald")
    static FString GetAbiVersion();

    UFUNCTION(BlueprintCallable, Category = "Root Herald")
    static FString GetLibraryVersion();

private:
    void* NativeHandle = nullptr;   // RootHeraldClient*
    static void* DllHandle;         // process-wide handle to the loaded native library
    static bool EnsureDllLoaded();
};
