# Nikaido Explorer v0.10.2 — Fix from real v0.10.1 diagnostics

GitHub Actions v0.10.1 resolvió correctamente AMSMB2 4.0.3, ZIPFoundation 0.9.20,
SWCompression 4.8.6, Unrar.swift 0.5.4 y BitByteData 2.1.0. También pasaron los
self-tests de `.sec`, Private Vault e índice.

El build iPhoneOS falló en un único punto:

`PrivateVaultSession.swift:659: error: 'nil' requires a contextual type`

La causa era un `Task.detached` cuyo tipo de retorno opcional no estaba declarado
de forma explícita. v0.10.2 lo fija como `Task<Data?, Never>` y mantiene intacta
la lógica del cache cifrado de miniaturas.

Esta corrección no migra ni reescribe la Vault.
