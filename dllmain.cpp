// dllmain.cpp : Defines the entry point for the DLL application.
#pragma comment(lib, "winmm.lib")

#include <loader.h>
#include <tinyxml2/tinyxml2.h>

#include <Windows.h>
#include <timeapi.h>
#include <tlhelp32.h>
#include <chrono>
#include <thread>

using namespace loader;

std::thread FovChanger;

bool playing;

// https://stackoverflow.com/a/55030118
DWORD FindProcessId(const std::wstring& processName)
{
    PROCESSENTRY32W processInfo;
    processInfo.dwSize = sizeof(processInfo);

    HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (processesSnapshot == INVALID_HANDLE_VALUE)
    {
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
    for (int i = 0; i < n; i++)
    {
        ReadProcessMemory(phandle, (LPCVOID)ptr, &ptrAddress, sizeof(ptrAddress), 0);
        if (ptrAddress == 0) return 0;
        ptr = ptrAddress + offsets[i];
    }
    return ptr;
}

int GetRefreshRate()
{
    DISPLAY_DEVICE displayDevice;
    DEVMODE displayMode;
    displayDevice.cb = sizeof(DISPLAY_DEVICE);
    displayMode.dmSize = sizeof(DEVMODE);
    int refreshRate = 30;
    for (int i = 0; EnumDisplayDevices(0, i, &displayDevice, 1); i++)
    {
        if (EnumDisplaySettings(displayDevice.DeviceName, ENUM_CURRENT_SETTINGS, &displayMode))
        {
            refreshRate = max(refreshRate, (int)displayMode.dmDisplayFrequency);
        }
    }
    return refreshRate;
}

void changeFov(float customFoV, bool forceConstantFoV, bool allowHighCpuUsage)
{
    DWORD procID = FindProcessId(L"MonsterHunterWorld.exe");
    HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procID);
    DWORD_PTR fovPointer = 0x140000000 + 0x05073ED0;
    DWORD_PTR fovPointerOffsets[] = { 0x58, 0x3A0 };
    DWORD_PTR fovAddress = 0;
    float fov = 53;
    float prevFov = 0;
    clock_t checkPointerTime = clock();
    int interval = 1000 / GetRefreshRate();
    if (!allowHighCpuUsage) timeBeginPeriod(interval);
    while (playing)
    {
        clock_t now = clock();
        if (fovAddress != 0)
        {
            ReadProcessMemory(phandle, (LPCVOID)fovAddress, &fov, sizeof(fov), 0);
            // increase FoV if it changed in-game
            if (fabsf(prevFov - fov) > 1)
            {
                float oldFov = fov;
                if (forceConstantFoV)
                {
                    prevFov = fov = customFoV;
                }
                else
                {
                    float multiplier = customFoV / 53;
                    prevFov = fov = fov * multiplier;
                }
                WriteProcessMemory(phandle, (LPVOID)fovAddress, &fov, sizeof(fov), 0);
                LOG(INFO) << "FoV Changer: " << oldFov << " -> " << fov;
            }
        }
        // check if the character logged in/out
        if (now - checkPointerTime > CLOCKS_PER_SEC)
        {
            checkPointerTime += CLOCKS_PER_SEC;
            fovAddress = FindPointerAddress(phandle, fovPointer, fovPointerOffsets, 2);
        }
        // wait for the next screen refresh
        if (!allowHighCpuUsage) {
            int delta = clock() - now;
            if (delta < interval)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(interval - delta));
            }
        }
    }
    if (!allowHighCpuUsage) timeEndPeriod(interval);
}

void onLoad()
{
    // check game version
    if (std::string(GameVersion) != "421470" && std::string(GameVersion) != "421471")
    {
        LOG(ERR) << "FoV Changer: Wrong version";
        return;
    }

    // read config file
    tinyxml2::XMLDocument doc;
    if (doc.LoadFile("nativePC\\plugins\\FoVChanger.xml"))
    {
        LOG(ERR) << "FoV Changer: Bad/Missing Config";
        return;
    }
    
    // read values from file
    float customFoV = doc.RootElement()->FirstChildElement("customFoV")->FloatAttribute("value", 59);
    bool forceConstantFoV = doc.RootElement()->FirstChildElement("forceConstantFoV")->BoolAttribute("value", false);
    bool allowHighCpuUsage = doc.RootElement()->FirstChildElement("allowHighCpuUsage")->BoolAttribute("value", false);
    
    // run main function loop
    playing = true;
    FovChanger = std::thread(changeFov, customFoV, forceConstantFoV, allowHighCpuUsage);
}

void onExit()
{
    playing = false;
    FovChanger.join();
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
        break;
    case DLL_PROCESS_DETACH:
        onExit();
        break;
    }
    return TRUE;
}

