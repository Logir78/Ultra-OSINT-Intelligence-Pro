# ============================================================================
#  NOCTUA Pro  ->  Subir el fix de IA a GitHub  (Windows PowerShell)
#  Sube TODO el repo (incluye el fix del shim de IA, commit 5697834) al repo
#  Ultra-OSINT-Intelligence-Pro. El token NO se guarda en disco ni en git.
# ============================================================================

$ErrorActionPreference = "Stop"
$RepoUrlBase = "github.com/Logir78/Ultra-OSINT-Intelligence-Pro.git"
$User        = "Logir78"

Write-Host "=== NOCTUA Pro - Subida a GitHub ===" -ForegroundColor Cyan

# 1) Situarse en la carpeta del script (donde estan .git y docker-compose.yml)
Set-Location -Path $PSScriptRoot

# 2) Verificar que es la carpeta correcta
if (-not (Test-Path ".git") -or -not (Test-Path "docker-compose.yml")) {
    Write-Host "ERROR: esta carpeta no es el repo (falta .git o docker-compose.yml)." -ForegroundColor Red
    Write-Host "Ejecuta este script DENTRO de la carpeta que descomprimiste." -ForegroundColor Yellow
    Read-Host "Pulsa Enter para salir"; exit 1
}

# 3) Confirmar que el fix esta presente
if (-not (Test-Path "backend/emergentintegrations/llm/chat.py")) {
    Write-Host "AVISO: no encuentro el fix del shim en esta carpeta." -ForegroundColor Red
    Read-Host "Pulsa Enter para salir"; exit 1
}
Write-Host "OK: repo correcto y fix del shim presente." -ForegroundColor Green
git log --oneline -1

# 4) Pedir el token (no se muestra, no se guarda)
$Secure = Read-Host "Pega tu GitHub token (ghp_...) y pulsa Enter" -AsSecureString
$BSTR   = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
$Token  = [Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

if ([string]::IsNullOrWhiteSpace($Token)) {
    Write-Host "ERROR: token vacio." -ForegroundColor Red
    Read-Host "Pulsa Enter para salir"; exit 1
}

# 5) Push forzado (el token va solo en esta llamada, no se persiste)
$PushUrl = "https://$($User):$($Token)@$RepoUrlBase"
Write-Host "Subiendo a GitHub (force)..." -ForegroundColor Cyan
git push $PushUrl main --force

# 6) Limpieza: asegurar que ningun remoto guarda el token
git remote remove origin 2>$null
$Token = $null

Write-Host ""
Write-Host "LISTO. El fix ya esta en GitHub." -ForegroundColor Green
Write-Host "IMPORTANTE: ve a GitHub -> Settings -> Developer settings -> Tokens y REVOCA/REGENERA este token (estuvo en el chat)." -ForegroundColor Yellow
Read-Host "Pulsa Enter para cerrar"
