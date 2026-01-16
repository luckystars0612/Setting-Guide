## Close VSCode
### Windows
```bash
taskkill /F /IM Code.exe
```
### Linux
```bash
pkill code
```
## Remove state file
### Windows
```bash
Remove-Item "$env:APPDATA\Code\User\globalStorage\storage.json" -Force
Remove-Item "$env:APPDATA\Code\storage.json" -Force -ErrorAction SilentlyContinue
```
### Linux
```bash
rm ~/.config/Code/User/globalStorage/storage.json
rm ~/.config/Code/storage.json 2>/dev/null
```
## settings.json
```bash
"window.restoreFullscreen": false,
```
