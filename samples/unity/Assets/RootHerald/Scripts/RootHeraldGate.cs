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
        [Tooltip("Publishable key; OK to embed in client builds.")]
        public string PublishableKey = "rh_pk_live_REPLACE_ME";

        [Tooltip("Base endpoint URL. Use https://rootherald.io for direct, "
               + "https://attest.<your-domain> for custom-domain transport mode.")]
        public string Endpoint = "https://rootherald.io";

        [Tooltip("Status text element; populated with the verdict at runtime.")]
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
        /// Demonstrates the RootHerald.Native usage pattern. The real call
        /// shape (RootHeraldClient ctor + VerifyAsync) is the same on every
        /// platform; only the underlying P/Invoke target differs.
        /// </summary>
        public async Task<bool> CheckSignup()
        {
            // The lines below reflect the RootHerald.Native NuGet wrapper's
            // public API from Wave 2. We comment them out so the sample
            // compiles even before the NuGet package is added to the
            // project — uncomment once you've installed RootHerald.Native.
            //
            //   using var client = new RootHerald.RootHeraldClient(
            //       apiKey:   PublishableKey,
            //       endpoint: Endpoint);
            //   var result = await client.VerifyAsync("signup");
            //   return result.Verdict == RootHerald.Verdict.Allow;

            await Task.Delay(250);  // stub — replace with the above.
            return true;
        }
    }
}
