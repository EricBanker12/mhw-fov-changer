// dllmain.cpp : Defines the entry point for the DLL application.
#include <filesystem>
#include <fstream>
#include <loader.h>
#include <nlohmann/json.hpp>
#include <tlhelp32.h>
#include <Windows.h>

using namespace loader;

nlohmann::json ConfigFile;

void onLoad()
{
    LOG(INFO) << "FoV Changer Loading...";
    if (std::string(GameVersion) != "404549") {
        LOG(ERR) << "FoV Changer: Wrong version";
        return;
    }

    ConfigFile = nlohmann::json::object();
    std::ifstream config("nativePC\\plugins\\FoVChanger.json");
    if (config.fail()) return;

    config >> ConfigFile;
    LOG(INFO) << "FoV Changer: Found config file";

    LOG(INFO) << "DONE !";
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        onLoad();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

