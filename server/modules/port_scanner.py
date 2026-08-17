import asyncio
import socket

async def scan(host, start_port, end_port, timeout=1.0):
    open_ports = []
    loop = asyncio.get_event_loop()

    async def check_port(port):
        try:
            conn = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            writer.close()
            await writer.wait_closed()
            open_ports.append(port)
        except:
            pass

    tasks = [check_port(p) for p in range(start_port, end_port+1)]
    await asyncio.gather(*tasks)
    return open_ports