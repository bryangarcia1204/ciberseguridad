import platform
import sys

system = platform.system()

if system == 'Windows':
    try:
        # Intentar usar la implementación nativa en C++ (process_list.py)
        from .process_list import get_process_list, get_process_by_pid, get_processes_by_name
    except ImportError:
        # Fallback a psutil
        import psutil
        def get_process_list():
            return [{'pid': p.info['pid'], 'name': p.info['name']} 
                    for p in psutil.process_iter(['pid', 'name'])]
        def get_process_by_pid(pid):
            try:
                p = psutil.Process(pid)
                return {'pid': p.pid, 'name': p.name()}
            except:
                return None
        def get_processes_by_name(name):
            return [{'pid': p.pid, 'name': p.info['name']} 
                    for p in psutil.process_iter(['pid', 'name']) if p.info['name'] == name]
elif system == 'Linux':
    # Asumiendo que tienes un módulo linux_proc.py para Linux
    try:
        from .linux_proc import get_process_list, get_process_by_pid, get_processes_by_name
    except ImportError:
        # Fallback genérico con psutil
        import psutil
        def get_process_list():
            return [{'pid': p.info['pid'], 'name': p.info['name']} 
                    for p in psutil.process_iter(['pid', 'name'])]
        def get_process_by_pid(pid):
            try:
                p = psutil.Process(pid)
                return {'pid': p.pid, 'name': p.name()}
            except:
                return None
        def get_processes_by_name(name):
            return [{'pid': p.pid, 'name': p.info['name']} 
                    for p in psutil.process_iter(['pid', 'name']) if p.info['name'] == name]