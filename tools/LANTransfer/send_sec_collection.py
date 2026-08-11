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

MAGIC = b"NXLINK04"
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
    identity: str


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

    # Protocol v3 stores one flat .sec collection. Never silently
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
                identity=(
                    f"zip:{info.CRC:08x}:"
                    f"{info.compress_size}:"
                    f"{info.header_offset}"
                ),
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

    files = []
    for source_path in files_on_disk:
        stat = source_path.stat()
        files.append(
            SourceFile(
                name=source_path.name,
                size=stat.st_size,
                opener=lambda p=source_path: p.open("rb", buffering=0),
                identity=(
                    f"file:{stat.st_size}:"
                    f"{stat.st_mtime_ns}"
                ),
            )
        )

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

    collection.files.sort(key=lambda item: item.name.casefold())

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



class TransportOpener:
    def __init__(self, aes: AESGCM):
        self.aes = aes
        self.sequence = 0

    def open(self, combined: bytes) -> bytes:
        if self.sequence > 0xFFFFFFFFFFFFFFFF:
            raise OverflowError("Secuencia de servidor agotada.")

        if len(combined) < 28:
            raise ValueError("Frame de Nikaido Link demasiado pequeño.")

        nonce = combined[:12]
        framed = self.aes.decrypt(nonce, combined[12:], None)

        if len(framed) < 8:
            raise ValueError("Frame de Nikaido Link inválido.")

        sequence = struct.unpack(">Q", framed[:8])[0]

        if sequence != self.sequence:
            raise ValueError(
                "Secuencia de respuesta de Nikaido Link inválida."
            )

        self.sequence += 1
        return framed[8:]


def recv_exact(sock: socket.socket, count: int) -> bytes:
    chunks = []
    remaining = count

    while remaining:
        chunk = sock.recv(remaining)

        if not chunk:
            raise ConnectionError(
                "El iPhone cerró la conexión antes de responder."
            )

        chunks.append(chunk)
        remaining -= len(chunk)

    return b"".join(chunks)


def recv_encrypted_json(sock, opener: TransportOpener):
    length = struct.unpack(">I", recv_exact(sock, 4))[0]

    if length < 28 or length > 16 * 1024 * 1024:
        raise ValueError("Respuesta de Nikaido Link con tamaño inválido.")

    encrypted = recv_exact(sock, length)
    raw = opener.open(encrypted)
    return json.loads(raw.decode("utf-8"))


def build_transfer_manifest(collection: SecCollection):
    files = [
        {
            "index": index,
            "name": item.name,
            "size": item.size,
            "identity": item.identity,
        }
        for index, item in enumerate(collection.files)
    ]

    canonical = json.dumps(
        {
            "folderName": collection.name,
            "files": files,
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")

    manifest_hash = hashlib.sha256(canonical).hexdigest()
    transfer_id = hashlib.sha256(
        b"NikaidoLink-v4\x00"
        + bytes.fromhex(manifest_hash)
        + collection.name.encode("utf-8")
    ).hexdigest()

    return transfer_id, manifest_hash


def progress(
    sent: int,
    total: int,
    started: float,
    baseline: int = 0,
) -> str:
    elapsed = max(0.001, time.monotonic() - started)
    session_bytes = max(0, sent - baseline)
    speed = session_bytes / elapsed
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
            "y los envía directamente a Nikaido Vault."
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
        transfer_id, manifest_hash = build_transfer_manifest(collection)

        transport_key = hashlib.sha256(secret).digest()
        aes = AESGCM(transport_key)
        sealer = TransportSealer(aes)
        opener = TransportOpener(aes)

        print()
        print("Nikaido Bridge / Link v4")
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
        resume_baseline = 0
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
                    "version": 4,
                    "transferID": transfer_id,
                    "manifestHash": manifest_hash,
                    "folderName": collection.name,
                    "fileCount": len(collection.files),
                    "totalSize": total_size,
                },
            )

            resume = recv_encrypted_json(sock, opener)

            if (
                resume.get("version") != 4
                or resume.get("type") != "resume"
                or resume.get("transferID", "").lower() != transfer_id
                or resume.get("manifestHash", "").lower() != manifest_hash
            ):
                raise ValueError(
                    "Respuesta de reanudación de Nikaido Link inválida."
                )

            if resume.get("alreadyCommitted") is True:
                committed_bytes = int(resume.get("completedBytes", -1))
                if committed_bytes != total_size:
                    raise ValueError(
                        "Nikaido Vault marcó la colección como confirmada con "
                        "un tamaño distinto al origen."
                    )

                print()
                print(
                    "[OK] Nikaido Vault ya había confirmado esta colección. "
                    "No se reenviará."
                )
                return 0

            completed_indexes = {
                int(value)
                for value in resume.get("completedIndexes", [])
            }

            if any(
                index < 0 or index >= len(collection.files)
                for index in completed_indexes
            ):
                raise ValueError(
                    "El iPhone devolvió índices de reanudación inválidos."
                )

            sent = int(resume.get("completedBytes", 0))

            expected_completed_bytes = sum(
                collection.files[index].size
                for index in completed_indexes
            )

            if sent != expected_completed_bytes:
                raise ValueError(
                    "El iPhone devolvió bytes de reanudación que no coinciden "
                    "con los archivos confirmados."
                )

            resume_baseline = sent
            started = time.monotonic()

            if sent < 0 or sent > total_size:
                raise ValueError(
                    "El iPhone devolvió un progreso de reanudación inválido."
                )

            if completed_indexes:
                print(
                    f"[RESUME] {len(completed_indexes):,} archivos ya estaban "
                    f"confirmados ({sent / (1024**3):.2f} GiB)."
                )

            for zero_index, item in enumerate(collection.files):
                if zero_index in completed_indexes:
                    continue

                index = zero_index + 1
                send_encrypted_json(
                    sock,
                    sealer,
                    {
                        "index": zero_index,
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
                                    resume_baseline,
                                ),
                                end="",
                                flush=True,
                            )
                            last_update = now

                if file_sent != item.size:
                    raise IOError(
                        f"Tamaño incorrecto al leer {item.name}."
                    )

            print("\n[INFO] Esperando commit cifrado de Nikaido Vault...")
            sock.settimeout(600)
            ack = recv_encrypted_json(sock, opener)

            if (
                ack.get("version") != 4
                or ack.get("type") != "committed"
                or ack.get("transferID", "").lower() != transfer_id
                or int(ack.get("fileCount", -1)) != len(collection.files)
                or int(ack.get("totalSize", -1)) != total_size
            ):
                raise ValueError(
                    "La confirmación final de Nikaido Vault es inválida."
                )

        print("\n")
        print("[OK] TRANSFERENCIA CONFIRMADA POR NIKAIDO VAULT.")
        print(
            "El índice cifrado fue guardado y la colección ya es persistente."
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
