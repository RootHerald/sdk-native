// Copyright Root Herald. Apache-2.0.

#include "Modules/ModuleManager.h"
#include "Modules/ModuleInterface.h"

class FRootHeraldUEModule : public IModuleInterface
{
public:
    virtual void StartupModule() override {}
    virtual void ShutdownModule() override {}
};

IMPLEMENT_MODULE(FRootHeraldUEModule, RootHeraldUE)
