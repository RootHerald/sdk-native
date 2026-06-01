// Copyright Root Herald. Apache-2.0.

using UnrealBuildTool;
using System.IO;

public class RootHeraldUE : ModuleRules
{
    public RootHeraldUE(ReadOnlyTargetRules Target) : base(Target)
    {
        PCHUsage = ModuleRules.PCHUsageMode.UseExplicitOrSharedPCHs;

        PublicDependencyModuleNames.AddRange(new[]
        {
            "Core",
            "CoreUObject",
            "Engine",
            "Projects",  // for IPluginManager
        });

        // Path to the bundled native artifacts (drop your platform-appropriate
        // RootHerald binary here before packaging).
        string PluginBinDir = Path.Combine(PluginDirectory, "Binaries");

        if (Target.Platform == UnrealTargetPlatform.Win64)
        {
            string DllName = "RootHerald.dll";
            PublicDelayLoadDLLs.Add(DllName);
            string DllPath = Path.Combine(PluginBinDir, "Win64", DllName);
            RuntimeDependencies.Add(DllPath);
            PublicDefinitions.Add("ROOTHERALD_DLL_NAME=TEXT(\"" + DllName + "\")");
        }
        else if (Target.Platform == UnrealTargetPlatform.Mac)
        {
            string Framework = "RootHeraldKit.framework";
            PublicAdditionalFrameworks.Add(new Framework(
                "RootHeraldKit",
                Path.Combine(PluginBinDir, "Mac", Framework)));
            PublicDefinitions.Add("ROOTHERALD_DLL_NAME=TEXT(\"RootHeraldKit\")");
        }
        else if (Target.Platform == UnrealTargetPlatform.Linux)
        {
            string SoName = "librootherald.so";
            string SoPath = Path.Combine(PluginBinDir, "Linux", SoName);
            RuntimeDependencies.Add(SoPath);
            PublicDefinitions.Add("ROOTHERALD_DLL_NAME=TEXT(\"" + SoName + "\")");
        }
    }
}
