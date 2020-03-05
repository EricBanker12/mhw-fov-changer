// dllmain.cpp : Defines the entry point for the DLL application.
#include <filesystem>
#include <fstream>
#include <loader.h>
#include <nlohmann/json.hpp>
#include <tlhelp32.h>
#include <Windows.h>

using namespace loader;

nlohmann::json ConfigFile;

// https://stackoverflow.com/a/55030118
DWORD FindProcessId(const std::wstring& processName)
{
    PROCESSENTRY32W processInfo;
    processInfo.dwSize = sizeof(processInfo);

    HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (processesSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    Process32FirstW(processesSnapshot, &processInfo);
    if (!processName.compare(processInfo.szExeFile))
    {
        CloseHandle(processesSnapshot);
        return processInfo.th32ProcessID;
    }

    while (Process32NextW(processesSnapshot, &processInfo))
    {
        if (!processName.compare(processInfo.szExeFile))
        {
            CloseHandle(processesSnapshot);
            return processInfo.th32ProcessID;
        }
    }

    CloseHandle(processesSnapshot);
    return 0;
}

DWORD_PTR FindPointerAddress(HANDLE phandle, DWORD_PTR ptr, DWORD_PTR offsets[], int n)
{
    DWORD_PTR ptrAddress;
    for (int i = 0; i < n; i++) {
        ReadProcessMemory(phandle, (LPCVOID)ptr, &ptrAddress, sizeof(ptrAddress), 0);
        ptr = ptrAddress + offsets[i];
    }
    return ptr;
}

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

    DWORD procID = FindProcessId(L"MonsterHunterWorld.exe");
    HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procID);
    DWORD_PTR fovPointer = 0x0;
    DWORD_PTR fovPointerOffsets[] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    DWORD_PTR fovAddress = FindPointerAddress(phandle, fovPointer, fovPointerOffsets, 7);
    float fovValue;
    ReadProcessMemory(phandle, (LPCVOID)fovAddress, &fovValue, sizeof(fovValue), 0);
    fovValue = fovValue * 1.2;
    WriteProcessMemory(phandle, (LPVOID)fovAddress, &fovValue, sizeof(fovValue), 0);

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

