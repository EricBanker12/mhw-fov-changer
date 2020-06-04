// dllmain.cpp : Defines the entry point for the DLL application.
#pragma comment(lib, "winmm.lib")
#include <filesystem>
#include <fstream>
#include <loader.h>
#include <nlohmann/json.hpp>
#include <timeapi.h>
#include <tlhelp32.h>
#include <Windows.h>
#include <chrono>
#include <thread>

using namespace loader;

nlohmann::json ConfigFile;

std::thread FovChanger;

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
        if (ptrAddress == 0) return 0;
        ptr = ptrAddress + offsets[i];
    }
    return ptr;
}

void changeFov()
{
    DWORD procID = FindProcessId(L"MonsterHunterWorld.exe");
    HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procID);
    DWORD_PTR fovPointer = 0x140000000 + 0x04F535D0;
    DWORD_PTR fovPointerOffsets[] = { 0x58, 0x3A0 };
    DWORD_PTR fovAddress = 0;
    float fov = 53;
    float prevFov = 0;
    INT16 i = 0;
    timeBeginPeriod(5);
    while (true)
    {
        if (i >= 200)
        {
            fovAddress = FindPointerAddress(phandle, fovPointer, fovPointerOffsets, 2);
            i = 0;
        }
        if (fovAddress != 0)
        {
            ReadProcessMemory(phandle, (LPCVOID)fovAddress, &fov, sizeof(fov), 0);
            if (fabsf(prevFov - fov) > 1)
            {
                float oldFov = fov;
                if (ConfigFile.value<bool>("forceConstantFoV", false))
                {
                    prevFov = fov = ConfigFile.value<float>("customFoV", 59);
                }
                else
                {
                    float multiplier = ConfigFile.value<float>("customFoV", 59) / 53;
                    prevFov = fov = fov * multiplier;
                }
                LOG(INFO) << "FoV Changer: " << oldFov << " -> " << fov;
                WriteProcessMemory(phandle, (LPVOID)fovAddress, &fov, sizeof(fov), 0);
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        i++;
    }
    timeEndPeriod(5);
}

void onLoad()
{
    if (std::string(GameVersion) != "410918") {
        LOG(ERR) << "FoV Changer: Wrong version";
        return;
    }

    ConfigFile = nlohmann::json::object();
    std::ifstream config("nativePC\\plugins\\FoVChanger.json");
    if (config.fail()) return;

    config >> ConfigFile;
    LOG(INFO) << "FoV Changer: Loaded config file";

    FovChanger = std::thread(changeFov);
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

