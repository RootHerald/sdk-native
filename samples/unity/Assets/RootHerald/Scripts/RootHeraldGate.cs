// RootHeraldGate.cs
//
// Drop this on a GameObject in your scene. Wire its public methods to your
// UI buttons (e.g. a sign-up / launch button). The gate calls into the
// managed RootHerald.Native wrapper (which P/Invokes RootHerald.dll on
// Windows / macOS, JNI on Android, and the XCFramework on iOS).
//
// Requires: RootHerald.Native NuGet package OR a hand-vendored copy of
// src/sdk-js/packages/native is NOT relevant here — for Unity you want the
// .NET wrapper. See src/clients/windows/dotnet/ for the C# binding.

using System;
using System.Threading.Tasks;
using UnityEngine;
using UnityEngine.UI;

// using RootHerald;  // .NET wrapper produced by Wave 2.

namespace RootHerald.UnitySample
{
    public class RootHeraldGate : MonoBehaviour
    {
        // ABI 3.0 — keyless client. There is NO key or endpoint to embed: the
        // client collects an evidence blob locally and hands it to YOUR backend,
        // which relays it to RootHerald (with its rh_sk_) and enforces the verdict.
        // Wire your backend's challenge nonce in, and send the evidence blob back.

        [Tooltip("Your backend's challenge endpoint (issues the nonce, relays the "
               + "evidence to RootHerald, returns the enforced verdict).")]
        public string BackendUrl = "https://api.your-game.example/rh";

        [Tooltip("Status text element; populated with the backend's verdict at runtime.")]
        public Text StatusText;

        [Tooltip("UI button that initiates the verify flow.")]
        public Button VerifyButton;

        private void Awake()
        {
            if (VerifyButton != null)
            {
                VerifyButton.onClick.AddListener(OnVerifyClicked);
            }
        }

        public async void OnVerifyClicked()
        {
            if (StatusText != null) StatusText.text = "Verifying…";
            VerifyButton.interactable = false;
            try
            {
                bool allowed = await CheckSignup();
                if (StatusText != null)
                    StatusText.text = allowed ? "ALLOW — proceeding" : "DENY — refused";
            }
            catch (Exception e)
            {
                if (StatusText != null) StatusText.text = $"Error: {e.Message}";
            }
            finally
            {
                VerifyButton.interactable = true;
            }
        }

        /// <summary>
        /// Demonstrates the keyless RootHerald.Native usage pattern. The client
        /// collects an evidence blob over a backend-issued nonce; your backend
        /// relays it and returns the enforced verdict. Same shape on every
        /// platform; only the underlying P/Invoke target differs.
        /// </summary>
        public async Task<bool> CheckSignup()
        {
            // The lines below reflect the keyless RootHerald.Native wrapper's API
            // (mirrors C ABI 3.0). Commented out so the sample compiles before the
            // package is added — uncomment once RootHerald.Native is installed.
            //
            //   string nonce = await MyBackend.GetChallengeNonce(BackendUrl);
            //   using var client = new RootHerald.RootHeraldClient();   // keyless
            //   string evidence = client.CollectEvidence(nonce);
            //   return await MyBackend.RelayAndVerify(BackendUrl, evidence);

            await Task.Delay(250);  // stub — replace with the above.
            return true;
        }
    }
}
