#!/usr/bin/env python3
import hashlib
import importlib.util
import json
from pathlib import Path
import socket
import struct
import tempfile
import zipfile

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = Path(__file__).resolve().parents[2]
SENDER = ROOT / "tools" / "LANTransfer" / "send_sec_collection.py"

spec = importlib.util.spec_from_file_location("solidsec_sender", SENDER)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def open_frame(secret: bytes, combined: bytes):
    key = hashlib.sha256(secret).digest()
    aes = AESGCM(key)
    nonce, ciphertext = combined[:12], combined[12:]
    framed = aes.decrypt(nonce, ciphertext, None)
    assert len(framed) >= 8
    sequence = struct.unpack(">Q", framed[:8])[0]
    return sequence, framed[8:]


with tempfile.TemporaryDirectory(prefix="solidsec-pc-selftest-") as td:
    root = Path(td)
    archive = root / "fixture.zip"

    # A large decoy *.sec without a 36-byte key candidate must NOT outrank
    # the smaller real collection.
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_STORED) as zf:
        for i in range(1_050):
            zf.writestr(f"backup/Decoy.sec/file{i:04d}", b"D")

        zf.writestr("backup/Photos.sec/keyCandidate", b"K" * 36)
        zf.writestr("backup/Photos.sec/fileOne", b"A" * 100)
        zf.writestr("backup/Photos.sec/fileTwo", b"B" * 200)
        zf.writestr("backup/ignore.txt", b"x")

    collection = module.find_sec_in_zip(archive)
    try:
        module.validate_collection(collection)
        assert collection.name == "Photos.sec"
        assert len(collection.files) == 3
        assert sum(f.size for f in collection.files) == 336
    finally:
        if collection.owner is not None:
            collection.owner.close()


    # A decoy explicit *.sec without a key must not prevent fallback to a
    # renamed real Solid folder that does contain the 36-byte key candidate.
    renamed_archive = root / "renamed-real.zip"
    with zipfile.ZipFile(renamed_archive, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("Decoy.sec/not-a-key", b"D" * 20)
        zf.writestr("RenamedVault/keyCandidate", b"K" * 36)
        zf.writestr("RenamedVault/fileOne", b"A" * 25)

    renamed_collection = module.find_sec_in_zip(renamed_archive)
    try:
        module.validate_collection(renamed_collection)
        assert renamed_collection.name == "RenamedVault.sec"
        assert len(renamed_collection.files) == 2
    finally:
        if renamed_collection.owner is not None:
            renamed_collection.owner.close()

    # Nested files must be rejected rather than silently omitted.
    nested_archive = root / "nested.zip"
    with zipfile.ZipFile(nested_archive, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("Nested.sec/keyCandidate", b"K" * 36)
        zf.writestr("Nested.sec/fileOne", b"A")
        zf.writestr("Nested.sec/sub/fileTwo", b"B")

    try:
        nested_collection = module.find_sec_in_zip(nested_archive)
    except ValueError as exc:
        assert "subcarpetas" in str(exc)
    else:
        if nested_collection.owner is not None:
            nested_collection.owner.close()
        raise AssertionError("nested .sec should have been rejected")

    # Direct folder discovery must behave the same way.
    direct = root / "Direct.sec"
    direct.mkdir()
    (direct / "keyCandidate").write_bytes(b"K" * 36)
    (direct / "fileOne").write_bytes(b"A" * 10)
    direct_collection = module.find_sec_folder(direct)
    module.validate_collection(direct_collection)
    assert direct_collection.name == "Direct.sec"
    assert len(direct_collection.files) == 2

    # If an explicit decoy .sec also has a 36-byte file, it still should not
    # automatically hide a stronger renamed collection.
    keyed_decoy_archive = root / "keyed-decoy.zip"
    with zipfile.ZipFile(keyed_decoy_archive, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("Decoy.sec/keyCandidate", b"D" * 36)
        zf.writestr("Decoy.sec/tiny", b"D")
        zf.writestr("RenamedStrong/keyCandidate", b"K" * 36)
        for i in range(20):
            zf.writestr(f"RenamedStrong/file{i:02d}", b"A" * 10)

    keyed_decoy_collection = module.find_sec_in_zip(keyed_decoy_archive)
    try:
        module.validate_collection(keyed_decoy_collection)
        assert keyed_decoy_collection.name == "RenamedStrong.sec"
        assert len(keyed_decoy_collection.files) == 21
    finally:
        if keyed_decoy_collection.owner is not None:
            keyed_decoy_collection.owner.close()

    # A nested 36-byte file inside an explicit .sec must not be reinterpreted as
    # a renamed independent collection to bypass nested-folder rejection.
    nested_key_archive = root / "nested-key.zip"
    with zipfile.ZipFile(nested_key_archive, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("Outer.sec/rootFile", b"A")
        zf.writestr("Outer.sec/sub/keyCandidate", b"K" * 36)
        zf.writestr("Outer.sec/sub/file", b"B")

    try:
        module.find_sec_in_zip(nested_key_archive)
        raise AssertionError("nested .sec key fallback bypass was accepted")
    except ValueError:
        pass

    # Unsafe ZIP traversal names must be rejected before any extraction/read.
    unsafe = root / "unsafe.zip"
    with zipfile.ZipFile(unsafe, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("../Escape.sec/keyCandidate", b"K" * 36)

    try:
        module.find_sec_in_zip(unsafe)
        raise AssertionError("unsafe traversal path was accepted")
    except ValueError:
        pass

    absolute = root / "absolute.zip"
    with zipfile.ZipFile(absolute, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("/Absolute.sec/keyCandidate", b"K" * 36)

    try:
        module.find_sec_in_zip(absolute)
        raise AssertionError("absolute ZIP path was accepted")
    except ValueError:
        pass

    # Verify exact framing helper interoperability independently from sockets.
    secret = bytes(range(16))
    aes = AESGCM(hashlib.sha256(secret).digest())
    sealer = module.TransportSealer(aes)
    payload = b"SolidSec transport frame"
    sealed0 = sealer.seal(payload)
    sealed1 = sealer.seal(b"next")
    seq0, opened0 = open_frame(secret, sealed0)
    seq1, opened1 = open_frame(secret, sealed1)
    assert (seq0, opened0) == (0, payload)
    assert (seq1, opened1) == (1, b"next")

    # send_encrypted_json must emit a 4-byte big-endian length followed by one
    # AES-GCM combined frame that can be decoded by the receiver model.
    left, right = socket.socketpair()
    try:
        metadata = {
            "version": 3,
            "folderName": "Photos.sec",
            "fileCount": 3,
            "totalSize": 336,
        }
        json_sealer = module.TransportSealer(aes)
        module.send_encrypted_json(left, json_sealer, metadata)
        length = struct.unpack(">I", right.recv(4))[0]
        frame = b""
        while len(frame) < length:
            frame += right.recv(length - len(frame))
        sequence, payload = open_frame(secret, frame)
        assert sequence == 0
        decoded = json.loads(payload.decode("utf-8"))
        assert decoded == metadata
    finally:
        left.close()
        right.close()

print("PC SENDER SELFTEST: OK")
