﻿# Diagnóstico SOMENTE LEITURA dos certificados autorizados do S-Cyber PM.
# Lê a lista CERTIFICADOS_AUTORIZADOS do appSCyberPM.py e confere, no repositório
# Pessoal do usuário atual, se cada certificado existe, tem chave privada e está válido.
# Não cria, não importa e não altera nada no Windows.
#
# Uso (PowerShell, nesta pasta, com o MESMO usuário que abre o aplicativo):
#   powershell -ExecutionPolicy Bypass -File .\verificar_certificados.ps1
$ErrorActionPreference = 'Stop'
$app = Join-Path $PSScriptRoot 'appSCyberPM.py'
$texto = [IO.File]::ReadAllText($app)
$bloco = [regex]::Match($texto, 'CERTIFICADOS_AUTORIZADOS\s*=\s*\[(.*?)\]', 'Singleline').Groups[1].Value
$lista = [regex]::Matches($bloco, '"([0-9A-Fa-f]{40})"') | ForEach-Object { $_.Groups[1].Value.ToUpperInvariant() }

Write-Host "=== Certificados autorizados no appSCyberPM.py: $(@($lista).Count) ==="
$agora = Get-Date
$algumOk = $false
foreach ($tp in $lista) {
    $c = Get-Item -Path "Cert:\CurrentUser\My\$tp" -ErrorAction SilentlyContinue
    if ($null -eq $c) {
        Write-Host "NAO INSTALADO NESTE USUARIO : $tp"
        continue
    }
    $valido = ($agora -ge $c.NotBefore) -and ($agora -le $c.NotAfter)
    $ok = $c.HasPrivateKey -and $valido
    if ($ok) { $algumOk = $true }
    Write-Host ("{0} : {1}" -f ($(if ($ok) { 'PRONTO PARA USO        ' } else { 'INSTALADO, MAS NAO SERVE' })), $tp)
    Write-Host "    Titular       : $($c.Subject)"
    Write-Host "    Chave privada : $($c.HasPrivateKey)"
    Write-Host "    Validade      : $($c.NotBefore.ToString('dd/MM/yyyy')) a $($c.NotAfter.ToString('dd/MM/yyyy'))"
}
Write-Host ''
if ($algumOk) {
    Write-Host 'RESULTADO: este usuario tem um certificado autorizado e pronto. O S-Cyber PM deve abrir.'
} else {
    Write-Host 'RESULTADO: nenhum certificado autorizado pronto neste usuario.'
    Write-Host 'Veja CERTIFICADOS.md: crie o seu certificado e acrescente o thumbprint a CERTIFICADOS_AUTORIZADOS.'
    Write-Host 'Importar so o arquivo .cer NAO resolve: ele nao tem a chave privada.'
}
