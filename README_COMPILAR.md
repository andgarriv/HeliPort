# README_COMPILAR

Guia rapida para compilar **itlwm** y **HeliPort** con soporte Enterprise (WPA2/WPA3, KEYAVAIL/KEYRUN, EAP-TTLS integrado en HeliPort).

## 1) Requisitos (macOS)

- Xcode 15 o superior
- Command Line Tools de Xcode
- `git`
- Homebrew (recomendado)

Instalar utilidades recomendadas:

```bash
brew install xcbeautify swiftlint wpa_supplicant
```

Verificar herramientas:

```bash
xcodebuild -version
swift --version
clang --version
which wpa_supplicant
which wpa_cli
```

## 2) Compilar itlwm (solo itlwm, no AirportItlwm)

Desde el repo `itlwm`:

```bash
cd ~/Desktop/macos/itlwm
git submodule update --init --recursive
[ -d MacKernelSDK ] || git clone --depth=1 https://github.com/acidanthera/MacKernelSDK.git

xcodebuild \
  -scheme itlwm \
  -configuration Debug \
  -derivedDataPath build \
  GIT_COMMIT=_local \
| xcbeautify
```

Salida esperada:

- `build/Build/Products/Debug/itlwm.kext`

## 3) Compilar HeliPort

Desde el repo `HeliPort`:

```bash
cd ~/Desktop/macos/HeliPort

xcodebuild \
  ARCHS=x86_64 ONLY_ACTIVE_ARCH=NO \
  -scheme HeliPort \
  -configuration Release \
  -derivedDataPath build \
  -disableAutomaticPackageResolution \
  CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO \
| xcbeautify
```

Salida esperada:

- `build/Build/Products/Release/HeliPort.app`

## 4) Despliegue minimo para pruebas

1. Copia `itlwm.kext` a tu EFI (OpenCore) en `EFI/OC/Kexts`.
2. Actualiza `config.plist` si cambiaste nombre/version o ruta.
3. Copia `HeliPort.app` a `/Applications`.
4. Reinicia.

## 5) WPA3-Enterprise EAP-TTLS (lo que necesita en runtime)

- `wpa_supplicant` y `wpa_cli` instalados (Homebrew recomendado).
- HeliPort pedira privilegios admin para lanzar el supplicant.
- Si en password pasas `pmk:<64hex>` (o `64hex`), HeliPort usa camino directo KEYAVAIL/KEYRUN.

## 6) Comprobaciones rapidas

Verifica que la app y driver se ven entre si:

- HeliPort no debe mostrar error de API mismatch.
- En logs de HeliPort debe aparecer la interfaz (ej. `en0`/`en1`) y estado de conexion.

Si falla EAP-TTLS:

- Revisa que exista `wpa_supplicant` en alguna de estas rutas:
  - `/opt/homebrew/sbin/wpa_supplicant`
  - `/usr/local/sbin/wpa_supplicant`
  - `/usr/sbin/wpa_supplicant`
- Revisa tambien `wpa_cli`:
  - `/opt/homebrew/bin/wpa_cli`
  - `/usr/local/bin/wpa_cli`
  - `/usr/sbin/wpa_cli`

## 7) Comandos utiles

Limpiar builds:

```bash
rm -rf ~/Desktop/macos/itlwm/build
rm -rf ~/Desktop/macos/HeliPort/build
```

Build Debug de HeliPort:

```bash
cd ~/Desktop/macos/HeliPort
xcodebuild \
  ARCHS=x86_64 ONLY_ACTIVE_ARCH=NO \
  -scheme HeliPort \
  -configuration Debug \
  -derivedDataPath build \
  -disableAutomaticPackageResolution \
  CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO \
| xcbeautify
```
