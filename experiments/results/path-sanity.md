# Path sanity check — WS12

- Malicious instances: 43; selected malicious paths: 615.
- Path-signature overlap with benign train: **0**; with benign test: **0**.

Top-3 rarest paths for three malicious instances:

## Instance 45
- `logR=-16.34` — P:reg EXECUTE F:c:/windows/system32/ntdll.dll
- `logR=-16.34` — P:reg EXECUTE F:c:/windows/system32/kernel32.dll
- `logR=-16.35` — P:reg EXECUTE F:c:/windows/system32/sechost.dll

## Instance 65
- `logR=-13.56` — P:taskhost EXECUTE F:c:/windows/system32/wldap32.dll
- `logR=-16.67` — P:taskhost EXECUTE F:c:/windows/system32/combase.dll
- `logR=-16.79` — P:taskhost EXECUTE F:c:/windows/system32/kernel.appcore.dll

## Instance 104
- `logR=-24.50` — P:powershell READ F:c:/windows/assembly/nativeimages_v4.0.30319_64/system.numerics/2ff6bcd99822ae7e2f8b960b90d4a9a5/system.numerics.ni.dll.aux
- `logR=-24.50` — P:powershell EXECUTE F:c:/windows/assembly/nativeimages_v4.0.30319_64/system.numerics/2ff6bcd99822ae7e2f8b960b90d4a9a5/system.numerics.ni.dll
- `logR=-24.50` — P:powershell READ F:c:/windows/assembly/nativeimages_v4.0.30319_64/system.management/03bb956308bb45f9549c8dde28a5298e/system.management.ni.dll.aux

