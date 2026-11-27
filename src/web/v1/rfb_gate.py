"""Pure-Python VNC DES auth helpers, RFB 3.8 handshake bridge, and streaming RFB Input Gate."""

from __future__ import annotations

import asyncio
import contextlib
import os
import struct
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Protocol

# Standard VNC ~/.vnc/passwd obfuscation key (already in FIPS 46-3 MSB-first bit order,
# matching TigerVNC/RealVNC d3des fixedkey {23, 82, 107, 6, 35, 78, 88, 7} bit-reversed).
_VNC_PASSWD_FIXED_KEY: bytes = bytes([0xE8, 0x4A, 0xD6, 0x60, 0xC4, 0x72, 0x1A, 0xE0])

DEFAULT_VNC_PASSWD_PATH: Path = Path.home() / ".vnc" / "passwd"

_MAX_RFB_BUFFER_BYTES: int = 16 * 1024 * 1024  # 16 MiB safety cap

# ---------------------------------------------------------------------------
# FIPS 46-3 Standard 56-bit DES Tables (1-indexed bit positions)
# ---------------------------------------------------------------------------

_IP: tuple[int, ...] = (
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7,
)

_FP: tuple[int, ...] = (
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25,
)

_E: tuple[int, ...] = (
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1,
)

_P: tuple[int, ...] = (
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25,
)

_PC1: tuple[int, ...] = (
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
)

_PC2: tuple[int, ...] = (
    14, 17, 11, 24, 1, 5, 3, 28,
    15, 6, 21, 10, 23, 19, 12, 4,
    26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56,
    34, 53, 46, 42, 50, 36, 29, 32,
)

_KEY_SHIFTS: tuple[int, ...] = (1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1)

_S_BOXES: tuple[tuple[tuple[int, ...], ...], ...] = (
    # S1
    (
        (14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7),
        (0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8),
        (4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0),
        (15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13),
    ),
    # S2
    (
        (15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10),
        (3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5),
        (0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15),
        (13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9),
    ),
    # S3
    (
        (10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8),
        (13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1),
        (13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7),
        (1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12),
    ),
    # S4
    (
        (7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15),
        (13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9),
        (10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4),
        (3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14),
    ),
    # S5
    (
        (2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9),
        (14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6),
        (4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14),
        (11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3),
    ),
    # S6
    (
        (12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11),
        (10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8),
        (9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6),
        (4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13),
    ),
    # S7
    (
        (4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1),
        (13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6),
        (1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2),
        (6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12),
    ),
    # S8
    (
        (13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7),
        (1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2),
        (7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8),
        (2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11),
    ),
)


class RfbHandshakeError(RuntimeError):
    """Raised when RFB 3.8 version negotiation or authentication fails."""


class RfbWebSocketProtocol(Protocol):
    """Minimal async WebSocket surface for RFB client handshake."""

    async def send_bytes(self, data: bytes) -> None: ...

    async def receive(self) -> Mapping[str, Any]: ...


def _reverse_bits(byte: int) -> int:
    """Reverse the 8 bits of a single byte (required for VNC DES keys)."""
    b = byte & 0xFF
    b = ((b & 0xF0) >> 4) | ((b & 0x0F) << 4)
    b = ((b & 0xCC) >> 2) | ((b & 0x33) << 2)
    b = ((b & 0xAA) >> 1) | ((b & 0x55) << 1)
    return b


def _permute(value: int, table: tuple[int, ...], in_bits: int) -> int:
    """Apply a 1-indexed FIPS 46-3 bit permutation table to an integer."""
    out = 0
    for pos in table:
        out = (out << 1) | ((value >> (in_bits - pos)) & 1)
    return out


def _des_subkeys(key_8: bytes) -> list[int]:
    """Derive 16 48-bit DES round subkeys from an 8-byte standard DES key."""
    if len(key_8) != 8:
        raise ValueError("DES key must be exactly 8 bytes.")
    key_int = int.from_bytes(key_8, "big")
    cd = _permute(key_int, _PC1, 64)
    c = (cd >> 28) & 0x0FFFFFFF
    d = cd & 0x0FFFFFFF
    subkeys: list[int] = []
    for shift in _KEY_SHIFTS:
        c = ((c << shift) | (c >> (28 - shift))) & 0x0FFFFFFF
        d = ((d << shift) | (d >> (28 - shift))) & 0x0FFFFFFF
        subkeys.append(_permute((c << 28) | d, _PC2, 56))
    return subkeys


def _des_crypt_block(key_8: bytes, block_8: bytes, *, decrypt: bool) -> bytes:
    """Encrypt or decrypt one 8-byte block using standard 56-bit DES-ECB."""
    if len(block_8) != 8:
        raise ValueError("DES block must be exactly 8 bytes.")
    subkeys = _des_subkeys(key_8)
    if decrypt:
        subkeys.reverse()

    block_int = int.from_bytes(block_8, "big")
    permuted = _permute(block_int, _IP, 64)
    left = (permuted >> 32) & 0xFFFFFFFF
    right = permuted & 0xFFFFFFFF

    for subkey in subkeys:
        expanded = _permute(right, _E, 32)
        xored = expanded ^ subkey
        s_out = 0
        for box_idx in range(8):
            chunk = (xored >> (42 - 6 * box_idx)) & 0x3F
            row = ((chunk >> 4) & 0x02) | (chunk & 0x01)
            col = (chunk >> 1) & 0x0F
            s_out = (s_out << 4) | _S_BOXES[box_idx][row][col]
        feistel = _permute(s_out, _P, 32)
        left, right = right, left ^ feistel

    preoutput = (right << 32) | left
    final = _permute(preoutput, _FP, 64)
    return final.to_bytes(8, "big")


def des_encrypt_block(key_8: bytes, block_8: bytes) -> bytes:
    """Encrypt a single 8-byte block with standard 56-bit DES (ECB)."""
    return _des_crypt_block(key_8, block_8, decrypt=False)


def des_decrypt_block(key_8: bytes, block_8: bytes) -> bytes:
    """Decrypt a single 8-byte block with standard 56-bit DES (ECB)."""
    return _des_crypt_block(key_8, block_8, decrypt=True)


def vnc_des_key(password: bytes) -> bytes:
    """Convert an up-to-8-byte VNC password into a bit-reversed 8-byte DES key."""
    padded = password[:8].ljust(8, b"\x00")
    return bytes(_reverse_bits(byte) for byte in padded)


def decrypt_vnc_passwd_file(passwd_path: Path) -> bytes | None:
    """Recover the up-to-8-byte VNC password strictly in memory from a vncpasswd file.

    Returns None if the file does not exist, cannot be read, or is malformed.
    The password is never logged, printed, or exposed.
    """
    try:
        if not passwd_path.is_file():
            return None
        raw = passwd_path.read_bytes()
    except OSError:
        return None
    if len(raw) < 8:
        return None
    decrypted = des_decrypt_block(_VNC_PASSWD_FIXED_KEY, raw[:8])
    return decrypted.split(b"\x00", 1)[0]


def solve_vnc_challenge(password: bytes, challenge_16: bytes) -> bytes:
    """Compute the standard 16-byte RFB Type 2 VNC Authentication response."""
    if len(challenge_16) != 16:
        raise ValueError("RFB VNC Auth challenge must be exactly 16 bytes.")
    key = vnc_des_key(password)
    return des_encrypt_block(key, challenge_16[:8]) + des_encrypt_block(key, challenge_16[8:16])


class RfbInputGate:
    """Streaming stateful Client-to-Server RFB 3.8 parser & human-input gate.

    Always allows framebuffer/pixel/encoding/sync requests (`0x00`, `0x02`, `0x03`, `0x96`, `0xF8`).
    Drops interactive input events (`0x04` KeyEvent, `0x05` PointerEvent, `0x06` ClientCutText,
    `0xFB` SetDesktopSize, `0xFF 0x00` QEMU ExtendedKeyEvent) whenever `allow_input` is False.
    Handles arbitrary TCP/WebSocket fragmentation without ever desyncing frame boundaries.
    """

    def __init__(self) -> None:
        self._buf = bytearray()
        self.dropped_input_events: int = 0
        self.forwarded_messages: int = 0

    @property
    def buffered_bytes(self) -> int:
        """Return number of incomplete trailing bytes currently buffered."""
        return len(self._buf)

    def reset(self) -> None:
        """Clear any buffered partial RFB bytes."""
        self._buf.clear()

    def feed(self, chunk: bytes, *, allow_input: bool) -> bytes:
        """Process an incoming client-to-server byte chunk and return allowed RFB bytes."""
        if not chunk:
            return b""
        if len(self._buf) + len(chunk) > _MAX_RFB_BUFFER_BYTES:
            self._buf.clear()
            raise ValueError("RFB input gate buffer limit exceeded.")
        self._buf.extend(chunk)
        out = bytearray()

        while self._buf:
            msg_type = self._buf[0]
            needed: int | None = None
            is_input = False

            if msg_type == 0x00:
                # SetPixelFormat: 20 bytes
                needed = 20
                is_input = False
            elif msg_type == 0x02:
                # SetEncodings: 4 + 4*n bytes
                if len(self._buf) < 4:
                    break
                (num_enc,) = struct.unpack("!H", self._buf[2:4])
                needed = 4 + 4 * int(num_enc)
                is_input = False
            elif msg_type == 0x03:
                # FramebufferUpdateRequest: 10 bytes
                needed = 10
                is_input = False
            elif msg_type == 0x04:
                # KeyEvent: 8 bytes
                needed = 8
                is_input = True
            elif msg_type == 0x05:
                # PointerEvent: 6 bytes
                needed = 6
                is_input = True
            elif msg_type == 0x06:
                # ClientCutText: 8 + length bytes
                if len(self._buf) < 8:
                    break
                (text_len,) = struct.unpack("!I", self._buf[4:8])
                needed = 8 + int(text_len)
                is_input = True
            elif msg_type == 0x96:
                # EnableContinuousUpdates: 10 bytes
                needed = 10
                is_input = False
            elif msg_type == 0xF8:
                # TightVNC/TigerVNC Fence: 9 + payload_len bytes
                if len(self._buf) < 9:
                    break
                payload_len = int(self._buf[8])
                needed = 9 + payload_len
                is_input = False
            elif msg_type == 0xFB:
                # SetDesktopSize: 8 + 16 * num_screens bytes
                if len(self._buf) < 8:
                    break
                num_screens = int(self._buf[6])
                needed = 8 + 16 * num_screens
                is_input = True
            elif msg_type == 0xFF:
                # QEMU / Extended Client Message
                if len(self._buf) < 2:
                    break
                sub_type = self._buf[1]
                if sub_type == 0x00:
                    # QEMU Extended Key Event: 12 bytes
                    needed = 12
                    is_input = True
                else:
                    # Unknown QEMU submessage: pass through only when input is allowed
                    if allow_input:
                        out.extend(self._buf)
                        self.forwarded_messages += 1
                    else:
                        self.dropped_input_events += 1
                    self._buf.clear()
                    break
            else:
                # Unknown RFB extension message: pass through only when input is allowed
                if allow_input:
                    out.extend(self._buf)
                    self.forwarded_messages += 1
                else:
                    self.dropped_input_events += 1
                self._buf.clear()
                break

            if needed is None or len(self._buf) < needed:
                break

            frame = bytes(self._buf[:needed])
            del self._buf[:needed]

            if is_input and not allow_input:
                self.dropped_input_events += 1
            else:
                out.extend(frame)
                self.forwarded_messages += 1

        return bytes(out)


def _parse_rfb_minor(version_bytes: bytes) -> int:
    """Parse minor protocol number from a 12-byte RFB version banner."""
    if len(version_bytes) != 12 or not version_bytes.startswith(b"RFB "):
        raise RfbHandshakeError("Invalid RFB protocol version banner.")
    try:
        minor_str = version_bytes[8:11].decode("ascii")
        return int(minor_str)
    except (UnicodeDecodeError, ValueError) as exc:
        raise RfbHandshakeError("Malformed RFB protocol version banner.") from exc


async def _read_rfb_reason(reader: asyncio.StreamReader) -> str:
    """Read an RFB 3.8 failure reason string if available."""
    with contextlib.suppress(asyncio.IncompleteReadError, OSError):
        raw_len = await reader.readexactly(4)
        (reason_len,) = struct.unpack("!I", raw_len)
        bounded = min(int(reason_len), 1024)
        if bounded > 0:
            raw_msg = await reader.readexactly(bounded)
            return raw_msg.decode("utf-8", errors="replace").strip()
    return ""


async def perform_backend_vnc_handshake(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    passwd_path: Path | None = None,
) -> None:
    """Perform RFB 3.8 (or 3.3/3.7) version & SecurityType negotiation with a local VNC server.

    Uses SecurityType None (1) transparently if the server offers it; otherwise authenticates
    using SecurityType VNC Auth (2) with the password decrypted in-memory from `passwd_path`.
    Upon return, the stream is positioned directly at ClientInit.
    """
    resolved_passwd_path = passwd_path
    if resolved_passwd_path is None:
        env_path = os.environ.get("GROKBOT_VNC_PASSWD_PATH", "").strip()
        resolved_passwd_path = Path(env_path).expanduser() if env_path else DEFAULT_VNC_PASSWD_PATH

    try:
        server_ver = await reader.readexactly(12)
    except asyncio.IncompleteReadError as exc:
        raise RfbHandshakeError("VNC backend closed during version handshake.") from exc

    server_minor = _parse_rfb_minor(server_ver)
    if server_minor >= 8:
        client_minor = 8
        writer.write(b"RFB 003.008\n")
    elif server_minor == 7:
        client_minor = 7
        writer.write(b"RFB 003.007\n")
    else:
        client_minor = 3
        writer.write(b"RFB 003.003\n")
    await writer.drain()

    try:
        if client_minor == 3:
            (sec_type_raw,) = struct.unpack("!I", await reader.readexactly(4))
            sec_type = int(sec_type_raw)
            if sec_type == 0:
                reason = await _read_rfb_reason(reader)
                raise RfbHandshakeError(f"VNC backend rejected connection: {reason or 'unknown'}")
            if sec_type == 1:
                return
            if sec_type != 2:
                raise RfbHandshakeError(f"Unsupported RFB 3.3 security type: {sec_type}")
            await _complete_backend_vnc_auth(
                reader,
                writer,
                resolved_passwd_path,
                read_reason=False,
            )
            return

        # RFB 3.7 / 3.8 security type list
        (num_types,) = struct.unpack("!B", await reader.readexactly(1))
        if int(num_types) == 0:
            reason = await _read_rfb_reason(reader)
            raise RfbHandshakeError(
                f"VNC backend offered no security types: {reason or 'unknown'}"
            )
        sec_types = list(await reader.readexactly(int(num_types)))

        if 1 in sec_types:
            # Prefer SecurityType None (1) if accepted by localhost VNC server
            writer.write(b"\x01")
            await writer.drain()
            if client_minor >= 8:
                (sec_result,) = struct.unpack("!I", await reader.readexactly(4))
                if int(sec_result) != 0:
                    reason = await _read_rfb_reason(reader)
                    raise RfbHandshakeError(
                        f"VNC backend SecurityType None failed: {reason or 'rejected'}"
                    )
            return

        if 2 in sec_types:
            writer.write(b"\x02")
            await writer.drain()
            await _complete_backend_vnc_auth(
                reader,
                writer,
                resolved_passwd_path,
                read_reason=(client_minor >= 8),
            )
            return

        raise RfbHandshakeError(f"VNC backend offered unsupported security types: {sec_types}")
    except asyncio.IncompleteReadError as exc:
        raise RfbHandshakeError(
            "VNC backend closed unexpectedly during security handshake."
        ) from exc


async def _complete_backend_vnc_auth(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    passwd_path: Path,
    *,
    read_reason: bool,
) -> None:
    password = decrypt_vnc_passwd_file(passwd_path)
    if password is None:
        raise RfbHandshakeError("VNC authentication required but password file is unavailable.")
    challenge = await reader.readexactly(16)
    response = solve_vnc_challenge(password, challenge)
    writer.write(response)
    await writer.drain()

    (sec_result,) = struct.unpack("!I", await reader.readexactly(4))
    if int(sec_result) != 0:
        reason = await _read_rfb_reason(reader) if read_reason else ""
        raise RfbHandshakeError(
            f"VNC backend authentication failed: {reason or 'invalid credentials'}"
        )


async def _ws_read_exact(
    ws: RfbWebSocketProtocol,
    count: int,
    buf: bytearray,
) -> bytes:
    """Read `count` bytes from binary WebSocket frames, keeping trailing bytes in `buf`."""
    while len(buf) < count:
        raw = await ws.receive()
        if raw.get("type") == "websocket.disconnect":
            raise RfbHandshakeError("Client WebSocket closed during RFB handshake.")
        chunk = raw.get("bytes")
        if not isinstance(chunk, (bytes, bytearray)) or not chunk:
            continue
        buf.extend(chunk)
    out = bytes(buf[:count])
    del buf[:count]
    return out


async def perform_client_none_handshake(ws: RfbWebSocketProtocol) -> bytes:
    """Negotiate RFB 3.8 with SecurityType None (1) with a browser noVNC client.

    Returns any trailing bytes that arrived coalesced after the security selection
    (for example, a coalesced 1-byte ClientInit).
    """
    buf = bytearray()
    await ws.send_bytes(b"RFB 003.008\n")
    client_ver = await _ws_read_exact(ws, 12, buf)
    client_minor = _parse_rfb_minor(client_ver)

    if client_minor <= 3:
        await ws.send_bytes(struct.pack("!I", 1))
        return bytes(buf)

    # Offer single SecurityType: None (1)
    await ws.send_bytes(b"\x01\x01")
    chosen_raw = await _ws_read_exact(ws, 1, buf)
    chosen_type = chosen_raw[0]
    if chosen_type != 1:
        if client_minor >= 8:
            msg = b"Unsupported security type"
            await ws.send_bytes(struct.pack("!II", 1, len(msg)) + msg)
        raise RfbHandshakeError(f"Client selected unsupported RFB security type: {chosen_type}")

    if client_minor >= 8:
        # SecurityResult OK
        await ws.send_bytes(b"\x00\x00\x00\x00")

    return bytes(buf)
