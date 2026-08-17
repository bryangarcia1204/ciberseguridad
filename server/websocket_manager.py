from fastapi import WebSocket
from typing import Dict, Set
from collections import defaultdict

class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[int, WebSocket] = {}
        self.connections_by_ip: Dict[str, Set[int]] = defaultdict(set)
        self.agent_ip: Dict[int, str] = {}
        self.max_connections_per_ip = 5
        self.max_total_connections = 1000  # Límite global
        self.pending_connections: Dict[str, int] = defaultdict(int)  # IP -> count
        self.max_pending_per_ip = 3

    async def connect(self, agent_id: int, websocket: WebSocket, client_ip: str) -> bool:
        """Acepta la conexión y la registra. Usar cuando la conexión no ha sido aceptada."""
         # Límite global
        if len(self.active_connections) >= self.max_total_connections:
            await websocket.close(code=1008, reason="Demasiadas conexiones totales")
            return False
        # Verificar límite por IP
        if len(self.connections_by_ip[client_ip]) >= self.max_connections_per_ip:
            await websocket.close(code=1008, reason="Demasiadas conexiones desde esta IP")
            return False
        
        if self.pending_connections[client_ip] >= self.max_pending_per_ip:
            await websocket.close(code=1008, reason="Demasiadas conexiones pendientes")
            return False
        self.pending_connections[client_ip] += 1

        # Si el agente ya tiene una conexión, cerrarla
        if agent_id in self.active_connections:
            try:
                await self.active_connections[agent_id].close(code=1008, reason="Nueva conexión")
            except:
                pass
            self._remove_agent(agent_id)

        await websocket.accept()
        self.active_connections[agent_id] = websocket
        self.connections_by_ip[client_ip].add(agent_id)
        self.agent_ip[agent_id] = client_ip
        self.pending_connections[client_ip] -= 1
        return True

    def add_connection(self, agent_id: int, websocket: WebSocket, client_ip: str) -> bool:
        """
        Agrega una conexión ya aceptada. No llama a accept().
        Útil cuando la aceptación se hizo fuera del manager.
        """
        if len(self.connections_by_ip[client_ip]) >= self.max_connections_per_ip:
            # No podemos cerrar aquí porque no tenemos control del websocket (ya aceptado)
            # Pero podemos rechazar lanzando una excepción o retornando False.
            return False

        if agent_id in self.active_connections:
            # No podemos cerrar la anterior aquí, pero podemos eliminarla
            self._remove_agent(agent_id)

        self.active_connections[agent_id] = websocket
        self.connections_by_ip[client_ip].add(agent_id)
        self.agent_ip[agent_id] = client_ip
        return True

    def _remove_agent(self, agent_id: int):
        if agent_id in self.active_connections:
            del self.active_connections[agent_id]
        if agent_id in self.agent_ip:
            ip = self.agent_ip[agent_id]
            if ip in self.connections_by_ip and agent_id in self.connections_by_ip[ip]:
                self.connections_by_ip[ip].remove(agent_id)
            del self.agent_ip[agent_id]

    async def disconnect(self, agent_id: int):
        if agent_id in self.active_connections:
            try:
                await self.active_connections[agent_id].close()
            except:
                pass
        self._remove_agent(agent_id)

    def disconnect_by_agent(self, agent_id: int, ip: str):
        self._remove_agent(agent_id)

    async def send_command(self, agent_id: int, command: dict):
        if agent_id in self.active_connections:
            await self.active_connections[agent_id].send_json(command)

manager = ConnectionManager()