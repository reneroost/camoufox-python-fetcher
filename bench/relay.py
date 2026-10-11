"""Byte-counting TCP relay: 127.0.0.1:8823 -> gw.dataimpulse.com:823.

Passes the proxy protocol through untouched (CONNECT, auth and TLS are end to end), and writes the
cumulative bytes in each direction to /tmp/relay-bytes.txt, so a caller can read the counter before
and after a fetch.
"""
import asyncio

UP, DOWN = 0, 0


def dump():
    with open("/tmp/relay-bytes.txt", "w") as f:
        f.write(f"{UP} {DOWN}\n")


async def pipe(reader, writer, direction):
    global UP, DOWN
    try:
        while data := await reader.read(65536):
            if direction == "up":
                UP += len(data)
            else:
                DOWN += len(data)
            writer.write(data)
            await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def handle(client_reader, client_writer):
    try:
        upstream_reader, upstream_writer = await asyncio.open_connection("gw.dataimpulse.com", 823)
    except Exception:
        client_writer.close()
        return
    await asyncio.gather(pipe(client_reader, upstream_writer, "up"),
                         pipe(upstream_reader, client_writer, "down"))


async def ticker():
    while True:
        dump()
        await asyncio.sleep(0.2)


async def main():
    server = await asyncio.start_server(handle, "127.0.0.1", 8823)
    asyncio.create_task(ticker())
    async with server:
        await server.serve_forever()

asyncio.run(main())
