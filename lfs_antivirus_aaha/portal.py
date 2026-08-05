"""XDG Desktop Portal file selection for the sandboxed Flatpak build."""

from __future__ import annotations

import asyncio
import uuid
from pathlib import Path
from urllib.parse import unquote, urlparse


def choose_portal_path(*, directory: bool, title: str) -> Path | None:
    """Synchronously obtain one user-granted local path from the file portal."""

    try:
        return asyncio.run(_choose_portal_path(directory=directory, title=title))
    except ImportError as exc:
        raise RuntimeError("The Flatpak file portal dependency is unavailable.") from exc


async def _choose_portal_path(*, directory: bool, title: str) -> Path | None:
    from dbus_next import BusType, Variant
    from dbus_next.aio import MessageBus

    bus = await MessageBus(bus_type=BusType.SESSION).connect()
    try:
        desktop_path = "/org/freedesktop/portal/desktop"
        introspection = await bus.introspect("org.freedesktop.portal.Desktop", desktop_path)
        proxy = bus.get_proxy_object("org.freedesktop.portal.Desktop", desktop_path, introspection)
        chooser = proxy.get_interface("org.freedesktop.portal.FileChooser")
        token = "aaha" + uuid.uuid4().hex
        request_path = await chooser.call_open_file(
            "",
            title,
            {
                "handle_token": Variant("s", token),
                "multiple": Variant("b", False),
                "directory": Variant("b", directory),
                "modal": Variant("b", True),
            },
        )
        request_intro = await bus.introspect("org.freedesktop.portal.Desktop", request_path)
        request_proxy = bus.get_proxy_object(
            "org.freedesktop.portal.Desktop", request_path, request_intro
        )
        request = request_proxy.get_interface("org.freedesktop.portal.Request")
        loop = asyncio.get_running_loop()
        response_future: asyncio.Future[tuple[int, dict[str, Variant]]] = loop.create_future()

        def receive_response(response: int, results: dict[str, Variant]) -> None:
            if not response_future.done():
                response_future.set_result((response, results))

        request.on_response(receive_response)
        response, results = await response_future
        if response != 0:
            return None
        uri_values = results.get("uris")
        if not uri_values or not uri_values.value:
            return None
        parsed = urlparse(str(uri_values.value[0]))
        if parsed.scheme != "file" or parsed.netloc not in {"", "localhost"}:
            raise RuntimeError("The portal returned a non-local scan target.")
        return Path(unquote(parsed.path))
    finally:
        bus.disconnect()
