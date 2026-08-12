# Nikaido Explorer v0.10.3 — LiveContainer Framework Fix

Corrección enfocada exclusivamente al crash de lanzamiento de v0.10.2 en LiveContainer. AMSMB2 ahora se enlaza **y se embebe** dentro de `SolidSecViewer.app/Frameworks`. La CI valida físicamente cada framework dinámico enlazado por `@rpath` antes de permitir crear la IPA.

No hay migración de Nikaido Vault ni cambios en sus datos.
