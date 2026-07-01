// Copyright Root Herald. Apache-2.0.

#pragma once

#include "CoreMinimal.h"
#include "UObject/NoExportTypes.h"
#include "RootHeraldClient.generated.h"

/**
 * Blueprint-callable Root Herald client (ABI 3.0 — keyless).
 *
 * Mirrors the C ABI in common/rootherald.h:
 *   Initialize       → RootHeraldClient_Create   (no key, no endpoint)
 *   CollectEvidence  → RootHeraldClient_CollectEvidence (per-attestation blob)
 *
 * The client holds no RootHerald key and opens no socket to RootHerald: it emits
 * an opaque evidence blob your game BACKEND relays to
 * POST /api/v1/attestations/verify (authenticated with its rh_sk_). The verdict
 * is computed and enforced server-side and never travels through the client.
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

    /** Load the native library and create the underlying keyless client handle. */
    UFUNCTION(BlueprintCallable, Category = "Root Herald")
    bool Initialize();

    /**
     * Collect a per-attestation evidence blob over a backend-issued base64 nonce.
     * Returns the evidence JSON to hand back to your backend for relay to
     * POST /api/v1/attestations/verify, or an empty string on failure.
     */
    UFUNCTION(BlueprintCallable, Category = "Root Herald")
    FString CollectEvidence(const FString& NonceB64);

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
