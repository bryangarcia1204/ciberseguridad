import os
import json
import hashlib
import asyncio
from modules.module_base import Module

def hash_file(filepath):
    sha = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for block in iter(lambda: f.read(4096), b''):
            sha.update(block)
    return sha.hexdigest()

def create_baseline(directory, baseline_file):
    baseline = {}
    for root, _, files in os.walk(directory):
        for file in files:
            path = os.path.join(root, file)
            try:
                baseline[path] = hash_file(path)
            except:
                pass
    with open(baseline_file, 'w') as f:
        json.dump(baseline, f, indent=4)
    return baseline

def check_integrity(baseline_file):
    with open(baseline_file) as f:
        baseline = json.load(f)
    changes = []
    for path, old_hash in baseline.items():
        if os.path.exists(path):
            if hash_file(path) != old_hash:
                changes.append(('modified', path))
        else:
            changes.append(('deleted', path))
    return changes

class IntegrityMonitorModule(Module):
    async def run(self):
        directory = self.config.get('directory', '/etc')
        baseline_file = self.config.get('baseline_file', 'baseline.json')
        interval = self.config.get('interval', 3600)
        loop = asyncio.get_event_loop()

        if not os.path.exists(baseline_file):
            await loop.run_in_executor(None, create_baseline, directory, baseline_file)
            await self.log('info', 'Baseline creado')

        while self.is_running:
            await asyncio.sleep(interval)
            changes = await loop.run_in_executor(None, check_integrity, baseline_file)
            # Dentro de IntegrityMonitorModule, en la alerta:
            if changes:
                for change in changes:
                     await self.store_data({'type': change[0], 'path': change[1]})
                await self.alert('integrity_change', f'Cambios detectados: {len(changes)}', {'changes': changes})
                await self.log('warning', f'Cambios: {changes}')
                # Opcional: actualizar baseline
                await loop.run_in_executor(None, create_baseline, directory, baseline_file)