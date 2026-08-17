import asyncio
from datetime import datetime, timedelta
from modules.module_base import Module
from database import SessionLocal, Event

class CleanupModule(Module):
    async def run(self):
        retention_days = self.config.get('retention_days', 30)
        interval = self.config.get('interval', 86400)  # 1 día
        while self.is_running:
            try:
                db = SessionLocal()
                cutoff = datetime.utcnow() - timedelta(days=retention_days)
                deleted = db.query(Event).filter(Event.timestamp < cutoff).delete()
                db.commit()
                await self.log('info', f'Eliminados {deleted} eventos antiguos (más de {retention_days} días)')
                db.close()
            except Exception as e:
                await self.log('error', f'Error en limpieza: {e}')
            await asyncio.sleep(interval)