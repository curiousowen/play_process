import ctypes
import sys
import os
import psutil

# Constants
PROCESS_ALL_ACCESS = 0x1F0FFF
VIRTUAL_MEM = (0x1000 | 0x2000)
PAGE_READWRITE = 0x04

# Load necessary libraries
kernel32 = ctypes.windll.kernel32
ntdll = ctypes.windll.ntdll

# Injection techniques
INJECTION_TECHNIQUES = {
    'CreateRemoteThread': 1,
    'NtCreateThreadEx': 2,
    'APC': 3
}

def inject_dll(pid, dll_path, method='CreateRemoteThread'):
    """
    Inject a DLL into a target process using the specified injection method.
    """
    dll_len = len(dll_path)
    
    # Get a handle to the process we are injecting into
    h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_process:
        print(f"Error: Could not get handle to process {pid}. Error Code: {ctypes.GetLastError()}")
        sys.exit(1)
    
    # Allocate memory within the process for the DLL
    arg_address = kernel32.VirtualAllocEx(h_process, 0, dll_len, VIRTUAL_MEM, PAGE_READWRITE)
    if not arg_address:
        print(f"Error: Could not allocate memory in process. Error Code: {ctypes.GetLastError()}")
        sys.exit(1)
    
    # Write the DLL path into the allocated memory
    written = ctypes.c_int(0)
    kernel32.WriteProcessMemory(h_process, arg_address, dll_path.encode('utf-8'), dll_len, ctypes.byref(written))
    
    # Resolve the address for LoadLibraryA
    h_kernel32 = kernel32.GetModuleHandleA(b'kernel32.dll')
    h_loadlib = kernel32.GetProcAddress(h_kernel32, b'LoadLibraryA')
    
    if method == 'CreateRemoteThread':
        # Create the remote thread using CreateRemoteThread
        thread_id = ctypes.c_ulong(0)
        if not kernel32.CreateRemoteThread(h_process, None, 0, h_loadlib, arg_address, 0, ctypes.byref(thread_id)):
            print(f"Error: Could not create remote thread. Error Code: {ctypes.GetLastError()}")
            sys.exit(1)
        print(f"Success: Injected {dll_path} using CreateRemoteThread into process {pid}")
    
    elif method == 'NtCreateThreadEx':
        # Define NtCreateThreadEx prototype and parameters
        NTSTATUS = ctypes.c_long
        HANDLE = ctypes.c_void_p
        PVOID = ctypes.c_void_p
        ULONG = ctypes.c_ulong
        SIZE_T = ctypes.c_size_t
        PHANDLE = ctypes.POINTER(HANDLE)
        
        class OBJECT_ATTRIBUTES(ctypes.Structure):
            _fields_ = [('Length', ULONG),
                        ('RootDirectory', HANDLE),
                        ('ObjectName', PVOID),
                        ('Attributes', ULONG),
                        ('SecurityDescriptor', PVOID),
                        ('SecurityQualityOfService', PVOID)]
        
        class CLIENT_ID(ctypes.Structure):
            _fields_ = [('UniqueProcess', PVOID),
                        ('UniqueThread', PVOID)]
        
        def NtCreateThreadEx(hThread, DesiredAccess, ObjectAttributes, ProcessHandle, StartAddress, Parameter, CreateSuspended, StackZeroBits, SizeOfStackCommit, SizeOfStackReserve, BytesBuffer):
            ntdll.NtCreateThreadEx.restype = NTSTATUS
            ntdll.NtCreateThreadEx.argtypes = [PHANDLE, ULONG, PVOID, HANDLE, PVOID, PVOID, ULONG, ULONG, ULONG, ULONG, PVOID]
            return ntdll.NtCreateThreadEx(ctypes.byref(hThread), 0x1FFFFF, None, ProcessHandle, StartAddress, Parameter, 0, 0, 0, 0, None)
        
        h_thread = HANDLE()
        status = NtCreateThreadEx(h_thread, 0x1FFFFF, None, h_process, h_loadlib, arg_address, 0, 0, 0, 0, None)
        
        if status != 0:
            print(f"Error: NtCreateThreadEx failed. Status Code: {status}")
            sys.exit(1)
        print(f"Success: Injected {dll_path} using NtCreateThreadEx into process {pid}")
    
    elif method == 'APC':
        # Queue a user APC to the process' threads
        def queue_apc(thread_id, address, parameter):
            thread_handle = kernel32.OpenThread(0x0020, False, thread_id)
            if not thread_handle:
                print(f"Warning: Could not open thread {thread_id}. Error Code: {ctypes.GetLastError()}")
                return False
            if not kernel32.QueueUserAPC(address, thread_handle, parameter):
                print(f"Warning: Could not queue APC. Error Code: {ctypes.GetLastError()}")
                return False
            kernel32.CloseHandle(thread_handle)
            return True
        
        # Get all thread IDs in the target process
        process = psutil.Process(pid)
        threads = process.threads()
        injected = False
        
        for thread in threads:
            if queue_apc(thread.id, h_loadlib, arg_address):
                injected = True
                print(f"Success: APC injected into thread {thread.id}")
                break
        
        if not injected:
            print("Error: APC injection failed. No suitable threads found.")
            sys.exit(1)
        print(f"Success: Injected {dll_path} using APC into process {pid}")
    
    else:
        print(f"Error: Unknown injection method: {method}")
        sys.exit(1)
    
    # Clean up
    kernel32.VirtualFreeEx(h_process, arg_address, 0, 0x8000)
    kernel32.CloseHandle(h_process)

if __name__ == "__main__":
    # Validate command-line arguments
    if len(sys.argv) < 3:
        print("Usage: python inject.py <pid> <dll_path> [<method>]")
        print("Methods: CreateRemoteThread, NtCreateThreadEx, APC")
        sys.exit(1)
    
    pid = int(sys.argv[1])
    dll_path = sys.argv[2]
    method = sys.argv[3] if len(sys.argv) > 3 else 'CreateRemoteThread'
    
    # Validate process ID
    if not psutil.pid_exists(pid):
        print(f"Error: Process ID {pid} does not exist.")
        sys.exit(1)
    
    # Validate DLL path
    if not os.path.isfile(dll_path):
        print(f"Error: DLL not found at path: {dll_path}")
        sys.exit(1)
    
    # Validate injection method
    if method not in INJECTION_TECHNIQUES:
        print(f"Error: Invalid injection method: {method}")
        print("Valid methods: CreateRemoteThread, NtCreateThreadEx, APC")
        sys.exit(1)
    
    # Perform DLL injection
    inject_dll(pid, dll_path, method)
