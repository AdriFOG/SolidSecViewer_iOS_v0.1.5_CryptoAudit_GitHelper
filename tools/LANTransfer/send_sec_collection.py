#!/usr/bin/env python3
import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import socket
import stat
import struct
import sys
import time
import zipfile

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except Exception:
    print("[ERROR] Falta el paquete 'cryptography'.")
    print("Ejecuta: python -m pip install cryptography")
    raise SystemExit(2)

MAGIC = b"SSVLAN03"
CHUNK = 1024 * 1024
MAX_FILE_COUNT = 200_000
MAX_TOTAL_SIZE = 100 * 1024 * 1024 * 1024
MAX_NAME_UTF8_BYTES = 1024
MAX_ZIP_ENTRIES = 500_000


@dataclass
class SourceFile:
    name: str
    size: int
    opener: object


@dataclass
class SecCollection:
    name: str
    files: list
    owner: object = None


def normalize_zip_name(name: str) -> str:
    # We never extract these paths on the PC, but still reject absolute/home-like
    # forms so discovery is deterministic and does not normalize a malformed ZIP
    # into a seemingly valid Solid collection.
    if not name or name.startswith(("/", "\\", "~")):
        raise ValueError(f"Ruta ZIP insegura: {name}")

    value = name.replace("\\", "/").strip("/")
    parts = [p for p in value.split("/") if p]

    if not parts:
        return ""

    for part in parts:
        if part in (".", "..") or ":" in part or "\x00" in part:
            raise ValueError(f"Ruta ZIP insegura: {name}")

    return "/".join(parts)


def find_sec_in_zip(path: Path) -> SecCollection:
    zf = zipfile.ZipFile(path, "r")
    infos = []

    for entry_index, info in enumerate(zf.infolist(), start=1):
        if entry_index > MAX_ZIP_ENTRIES:
            zf.close()
            raise ValueError(
                f"El ZIP contiene más de {MAX_ZIP_ENTRIES:,} entradas; "
                "se rechazó para evitar un escaneo abusivo."
            )

        if info.is_dir():
            continue

        unix_mode = (info.external_attr >> 16) & 0xFFFF
        if unix_mode and stat.S_ISLNK(unix_mode):
            zf.close()
            raise ValueError(
                f"El ZIP contiene un enlace simbólico no permitido: {info.filename}"
            )

        normalized = normalize_zip_name(info.filename)

        if normalized:
            infos.append((normalized, info))

    if not infos:
        zf.close()
        raise ValueError("El ZIP no contiene archivos.")

    candidates = {}

    for normalized, info in infos:
        parts = normalized.split("/")

        for index, part in enumerate(parts[:-1]):
            if part.lower().endswith(".sec"):
                root = "/".join(parts[: index + 1])
                candidate = candidates.setdefault(
                    root,
                    {"files": [], "key": 0, "bytes": 0},
                )

                relative = normalized[len(root):].lstrip("/")

                # Only direct children belong to the flat format supported by
                # this build. Nested entries are detected/rejected later and do
                # not get to provide the .key signal used for candidate ranking.
                if relative and "/" not in relative:
                    candidate["files"].append((relative, info))
                    candidate["bytes"] += info.file_size

                    if info.file_size == 36:
                        candidate["key"] += 1

                candidates[root] = candidate
                break

    # Fallback: parent containing a direct 36-byte file. Build parent groups in
    # O(n), not O(n²); a hostile ZIP with many 36-byte entries must not turn the
    # scanner into millions/billions of comparisons.
    direct_by_parent = {}

    for normalized, info in infos:
        parts = normalized.split("/")
        if len(parts) < 2:
            continue
        parent = "/".join(parts[:-1])
        direct_by_parent.setdefault(parent, []).append((parts[-1], info))

    fallback = {}
    explicit_roots = tuple(candidates.keys())

    for parent, direct in direct_by_parent.items():
        key_count = sum(1 for _, info in direct if info.file_size == 36)
        if key_count == 0:
            continue

        # Never reinterpret a nested directory INSIDE an explicit .sec as a
        # renamed top-level Solid folder; doing that could bypass nested-folder
        # rejection and silently transfer only part of the collection.
        if any(parent.startswith(root + "/") for root in explicit_roots):
            continue

        fallback[parent] = {
            "files": direct,
            "key": key_count,
            "bytes": sum(info.file_size for _, info in direct),
        }

    if not candidates and not fallback:
        zf.close()
        raise ValueError("No encontré una carpeta .sec dentro del ZIP.")

    def score(item):
        _, data = item
        return (
            data["key"] * 1_000_000_000
            + len(data["files"]) * 1_000_000
            + min(data["bytes"], 999_999)
        )

    # Do not let a huge directory merely named *.sec outrank a real Solid
    # collection: every eligible candidate needs the 36-byte .key signal. Rank
    # explicit and renamed candidates together so an unrelated decoy *.sec does
    # not automatically hide a stronger renamed collection.
    eligible = {
        root: (data, False)
        for root, data in candidates.items()
        if data["key"] > 0
    }
    for fallback_root, fallback_data in fallback.items():
        current = eligible.get(fallback_root)
        if current is None or score((fallback_root, fallback_data)) > score((fallback_root, current[0])):
            eligible[fallback_root] = (fallback_data, True)

    if eligible:
        root, (data, used_fallback) = max(
            eligible.items(),
            key=lambda item: score((item[0], item[1][0])),
        )
    else:
        zf.close()
        raise ValueError(
            "No encontré una carpeta .sec con archivo .key cifrado de 36 bytes."
        )

    # Protocol v3 stores one flat Solid Explorer collection. Never silently
    # ignore nested entries: that could make a transfer look successful while
    # omitting data. Reject and ask for a flat .sec until recursive semantics
    # have been reverse-engineered/tested.
    prefix = root + "/"
    nested = []
    for normalized, info in infos:
        if not normalized.startswith(prefix):
            continue
        relative = normalized[len(prefix):]
        if relative and "/" in relative:
            nested.append(relative)
            if len(nested) >= 3:
                break

    if nested:
        zf.close()
        examples = ", ".join(nested)
        raise ValueError(
            "La carpeta .sec contiene subcarpetas. Esta build no las omite "
            f"silenciosamente; ejemplos: {examples}"
        )

    if not data["files"]:
        zf.close()
        raise ValueError("La carpeta .sec encontrada está vacía.")

    if not any(info.file_size == 36 for _, info in data["files"]):
        zf.close()
        raise ValueError(
            "La carpeta candidata no contiene el archivo .key cifrado de 36 bytes."
        )

    files = []

    for relative, info in data["files"]:
        if info.flag_bits & 0x1:
            zf.close()
            raise ValueError(
                "El ZIP está protegido con contraseña. Usa un ZIP normal; "
                "la carpeta .sec ya está cifrada."
            )

        files.append(
            SourceFile(
                name=PurePosixPath(relative).name,
                size=info.file_size,
                opener=lambda info=info: zf.open(info, "r"),
            )
        )

    collection_name = PurePosixPath(root).name
    if used_fallback and not collection_name.lower().endswith(".sec"):
        collection_name += ".sec"

    return SecCollection(
        name=collection_name,
        files=files,
        owner=zf,
    )


def find_sec_folder(path: Path) -> SecCollection:
    if not path.is_dir():
        raise ValueError("No es una carpeta.")

    children = list(path.iterdir())

    if any(p.is_symlink() for p in children):
        raise ValueError(
            "La carpeta .sec contiene enlaces simbólicos; no se seguirán."
        )

    files_on_disk = [p for p in children if p.is_file()]

    if any(p.is_dir() for p in children):
        raise ValueError(
            "La carpeta .sec contiene subcarpetas. Esta build exige una "
            "colección plana para no omitir archivos sin avisar."
        )

    if not files_on_disk:
        raise ValueError("La carpeta .sec está vacía.")

    if not any(p.stat().st_size == 36 for p in files_on_disk):
        raise ValueError(
            "No encontré el archivo .key cifrado de 36 bytes."
        )

    files = [
        SourceFile(
            name=p.name,
            size=p.stat().st_size,
            opener=lambda p=p: p.open("rb", buffering=0),
        )
        for p in files_on_disk
    ]

    name = path.name

    if not name.lower().endswith(".sec"):
        name += ".sec"

    return SecCollection(name=name, files=files)


def discover(path: Path) -> SecCollection:
    if path.is_dir():
        return find_sec_folder(path)

    if path.is_file() and path.suffix.lower() == ".zip":
        return find_sec_in_zip(path)

    raise ValueError("Selecciona un ZIP o una carpeta .sec.")




def validate_collection(collection: SecCollection) -> None:
    collection_name = collection.name
    if (
        not collection_name
        or not collection_name.lower().endswith(".sec")
        or collection_name in (".", "..")
        or "/" in collection_name
        or "\\" in collection_name
        or ":" in collection_name
        or "\x00" in collection_name
        or len(collection_name.encode("utf-8")) > MAX_NAME_UTF8_BYTES
    ):
        raise ValueError("Nombre de colección .sec inválido.")

    if not collection.files:
        raise ValueError("La colección .sec está vacía.")

    if len(collection.files) > MAX_FILE_COUNT:
        raise ValueError("La colección contiene demasiados archivos.")

    names = set()
    total = 0

    for item in collection.files:
        name = item.name
        if (
            not name
            or name in (".", "..")
            or "/" in name
            or "\\" in name
            or ":" in name
            or "\x00" in name
            or len(name.encode("utf-8")) > MAX_NAME_UTF8_BYTES
        ):
            raise ValueError(f"Nombre .sec inválido: {name!r}")

        if name in names:
            raise ValueError(f"Nombre duplicado dentro de .sec: {name}")

        names.add(name)
        total += item.size

        if total > MAX_TOTAL_SIZE:
            raise ValueError("La colección supera el límite de 100 GB.")

    if not any(item.size == 36 for item in collection.files):
        raise ValueError("No encontré el archivo .key cifrado de 36 bytes.")

def clean_token(text: str) -> bytes:
    value = text.replace("-", "").replace(" ", "").strip()

    if len(value) != 32:
        raise ValueError(
            "El código debe contener 32 caracteres hexadecimales."
        )

    return bytes.fromhex(value)


class TransportSealer:
    def __init__(self, aes: AESGCM):
        self.aes = aes
        self.sequence = 0

    def seal(self, plaintext: bytes) -> bytes:
        if self.sequence > 0xFFFFFFFFFFFFFFFF:
            raise OverflowError("Secuencia de transporte agotada.")

        framed = struct.pack(">Q", self.sequence) + plaintext
        self.sequence += 1
        nonce = os.urandom(12)
        return nonce + self.aes.encrypt(nonce, framed, None)


def send_u32(sock: socket.socket, value: int) -> None:
    sock.sendall(struct.pack(">I", value))


def send_encrypted_json(sock, sealer: TransportSealer, payload):
    raw = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")

    encrypted = sealer.seal(raw)
    send_u32(sock, len(encrypted))
    sock.sendall(encrypted)


def progress(sent: int, total: int, started: float) -> str:
    elapsed = max(0.001, time.monotonic() - started)
    speed = sent / elapsed
    percent = (sent / total * 100.0) if total else 0.0
    remaining = max(0, total - sent) / speed if speed > 0 else 0

    return (
        f"{percent:6.2f}%  "
        f"{sent / (1024**3):.2f}/{total / (1024**3):.2f} GiB  "
        f"{speed / (1024**2):.1f} MiB/s  "
        f"ETA {remaining / 60:.1f} min"
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Extrae por streaming solo los archivos cifrados .sec "
            "y los envía directamente a Mi bóveda."
        )
    )
    parser.add_argument("source", help="ZIP o carpeta .sec")
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--token", required=True)
    args = parser.parse_args()

    source_path = Path(args.source).expanduser().resolve()

    try:
        collection = discover(source_path)
        validate_collection(collection)
        secret = clean_token(args.token)
    except Exception as exc:
        print(f"[ERROR] {exc}")
        return 2

    try:
        total_size = sum(item.size for item in collection.files)

        transport_key = hashlib.sha256(secret).digest()
        aes = AESGCM(transport_key)
        sealer = TransportSealer(aes)

        print()
        print("SolidSec LAN Transfer v3")
        print("========================")
        print(f"Colección : {collection.name}")
        print(f"Archivos  : {len(collection.files):,}")
        print(f"Datos .sec: {total_size / (1024**3):.2f} GiB")
        print()
        print(
            "El ZIP NO se enviará ni se guardará en el iPhone. "
            "Solo se transmitirán sus archivos .sec cifrados."
        )
        print()

        started = time.monotonic()
        sent = 0
        last_update = 0.0

        with socket.create_connection(
            (args.host, args.port),
            timeout=30,
        ) as sock:
            sock.settimeout(60)
            sock.setsockopt(
                socket.IPPROTO_TCP,
                socket.TCP_NODELAY,
                1,
            )

            sock.sendall(MAGIC)

            send_encrypted_json(
                sock,
                sealer,
                {
                    "version": 3,
                    "folderName": collection.name,
                    "fileCount": len(collection.files),
                    "totalSize": total_size,
                },
            )

            for index, item in enumerate(collection.files, start=1):
                send_encrypted_json(
                    sock,
                    sealer,
                    {
                        "filename": item.name,
                        "size": item.size,
                    },
                )

                print(
                    f"\n[{index}/{len(collection.files)}] {item.name}"
                )

                with item.opener() as source:
                    file_sent = 0

                    while file_sent < item.size:
                        chunk = source.read(
                            min(CHUNK, item.size - file_sent)
                        )

                        if not chunk:
                            raise IOError(
                                f"{item.name} terminó antes de tiempo."
                            )

                        encrypted = sealer.seal(chunk)
                        send_u32(sock, len(encrypted))
                        sock.sendall(encrypted)

                        file_sent += len(chunk)
                        sent += len(chunk)

                        now = time.monotonic()

                        if (
                            now - last_update >= 0.5
                            or sent == total_size
                        ):
                            print(
                                "\r" + progress(
                                    sent,
                                    total_size,
                                    started,
                                ),
                                end="",
                                flush=True,
                            )
                            last_update = now

                if file_sent != item.size:
                    raise IOError(
                        f"Tamaño incorrecto al leer {item.name}."
                    )

        print("\n")
        print("[OK] Colección .sec enviada.")
        print(
            "Espera a que el iPhone confirme "
            "'Colección .sec guardada'."
        )
        return 0

    except KeyboardInterrupt:
        print("\n[CANCELADO] Transferencia cancelada.")
        return 130

    except Exception as exc:
        print(f"\n[ERROR] {exc}")
        return 1

    finally:
        if getattr(collection, "owner", None) is not None:
            collection.owner.close()


if __name__ == "__main__":
    raise SystemExit(main())
