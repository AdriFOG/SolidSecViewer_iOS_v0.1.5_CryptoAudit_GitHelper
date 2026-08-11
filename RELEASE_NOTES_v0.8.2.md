NIKAIDO EXPLORER iOS v0.8.2 — VIDEO THUMBNAILS
================================================

RUNTIME REPORT FIXED
--------------------
Videos already played correctly, but the galleries showed only a generic film
icon. v0.8.2 adds real poster-frame thumbnails.

AFFECTED GALLERIES
------------------
1. Stored encrypted .sec collections inside Nikaido Vault.
2. Regular image/video files stored directly in Nikaido Vault.
3. Directly opened .sec folders.

PRIVACY MODEL
-------------
No complete plaintext video file is created for a thumbnail.

Video posters are generated through AVAssetImageGenerator over the same
authenticated random-access loaders used by playback:
- outer Nikaido Vault AES-256-GCM random access when applicable;
- inner .sec AES-256-CTR random access when applicable;
- AVFoundation requests only the media ranges it needs.

Poster images derived from Nikaido Vault media are persisted only as small
AES-GCM sealed JPEG cache files:
  Application Support/SolidSecPrivateVault/thumbnails/<entry UUID>.nkt

The old internal Application Support directory name is intentionally unchanged
for data-container compatibility. The .nkt files contain encrypted thumbnail
bytes, not plaintext JPEG files.

LEGACY STORED .SEC VIDEOS
-------------------------
A video imported before random-access manifests existed may require one
authenticated full scan the first time its poster is generated. This does NOT:
- copy the video;
- rewrite the multi-GB .ssvb blob;
- move the collection.

Only authenticated random-access metadata and a small encrypted poster are
persisted. Poster generation is serialized to one legacy video at a time.
Scrolling away cancels the long preparation path.

Videos that were already opened in v0.8.1 generally already have their
random-access manifest, so their thumbnails should be much faster to generate.

UI
--
- Real video poster frame.
- Play-circle overlay remains visible on videos.
- Progress spinner while a first poster is being prepared.
- A short gallery note explains that old videos may need one initial pass.

COMPATIBILITY
-------------
Bundle ID remains:
  com.teamnikaido.solidsecviewer

Vault verifier bytes remain:
  SolidSecPrivateVault-v1

Vault config format remains v1.
Existing .ssvb blobs are unchanged.

EXPECTED IPA
------------
NikaidoExplorer-LiveContainer-v0.8.2.ipa
