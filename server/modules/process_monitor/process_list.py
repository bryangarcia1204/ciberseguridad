import ctypes
from ctypes import wintypes

class ProcessInfo(ctypes.Structure):
    _fields_ = [
        ("pid", wintypes.DWORD),
        ("name", ctypes.c_wchar * 260),
        ("parent_pid", wintypes.DWORD)
    ]

# Cargar el DLL (debe estar en el mismo directorio o en PATH)
try:
    _dll = ctypes.CDLL("./process_list.dll")
except Exception as e:
    raise ImportError("No se pudo cargar process_list.dll") from e

_dll.GetProcessList.argtypes = [ctypes.POINTER(ProcessInfo), ctypes.c_int]
_dll.GetProcessList.restype = ctypes.c_int

def get_process_list():
    """
    Devuelve una lista de diccionarios con información de procesos activos.
    Cada diccionario contiene: pid, name, parent_pid.
    """
    max_procs = 1024
    arr = (ProcessInfo * max_procs)()
    count = _dll.GetProcessList(arr, max_procs)
    if count < 0:
        return []
    result = []
    for i in range(count):
        result.append({
            'pid': arr[i].pid,
            'name': arr[i].name,
            'parent_pid': arr[i].parent_pid
        })
    return result

def get_process_by_pid(pid):
    """Busca un proceso por su PID y devuelve su información o None."""
    procs = get_process_list()
    for p in procs:
        if p['pid'] == pid:
            return p
    return None

def get_processes_by_name(name):
    """Devuelve una lista de procesos cuyo nombre coincida (case-insensitive)."""
    procs = get_process_list()
    name_lower = name.lower()
    return [p for p in procs if p['name'].lower() == name_lower]