import os

def get_process_list():
    processes = []
    for pid in os.listdir('/proc'):
        if pid.isdigit():
            try:
                with open(f'/proc/{pid}/comm', 'r') as f:
                    name = f.read().strip()
                # También podemos obtener el PPID de /proc/{pid}/stat
                with open(f'/proc/{pid}/stat', 'r') as f:
                    stat = f.read().split()
                    ppid = int(stat[3])
                processes.append({
                    'pid': int(pid),
                    'name': name,
                    'parent_pid': ppid
                })
            except (IOError, OSError, IndexError):
                continue
    return processes

def get_process_by_pid(pid):
    for p in get_process_list():
        if p['pid'] == pid:
            return p
    return None

def get_processes_by_name(name):
    name_lower = name.lower()
    return [p for p in get_process_list() if p['name'].lower() == name_lower]