# Diagnóstico somente leitura do certificado já existente no S-Cyber PM.
# Executar no PowerShell com o MESMO usuário Windows que abre a aplicação.
# Não cria certificados, não importa arquivos e não modifica o Windows.
$ErrorActionPreference = 'Stop'
$arquivo = Join-Path $PSScriptRoot 'certificados\S-Cyber PM.cer'
$certificadoArquivo = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($arquivo)
$thumbArquivo = ($certificadoArquivo.Thumbprint -replace '[^0-9A-Fa-f]','').ToUpperInvariant()
$thumbCodigo = 'ECD4B39DE69C171732449C0D8378F312661482DA'
$thumbAnterior = '1046998520BF09EAF69CEF2AD55DA1ED739A1E6C'
Write-Host '=== Certificado fornecido no projeto original ==='
Write-Host "Subject       : $($certificadoArquivo.Subject)"
Write-Host "Thumbprint    : $thumbArquivo"
Write-Host "Validade final: $($certificadoArquivo.NotAfter)"
Write-Host "Mesmo do codigo integrado: $($thumbArquivo -eq $thumbCodigo)"
Write-Host ''
Write-Host '=== Certificados no repositorio Pessoal do usuario atual ==='
foreach ($tp in @($thumbCodigo,$thumbAnterior) | Select-Object -Unique) {
    $c = Get-Item -Path "Cert:\CurrentUser\My\$tp" -ErrorAction SilentlyContinue
    if ($null -eq $c) {
        Write-Host "NAO ENCONTRADO : $tp"
    } else {
        Write-Host "ENCONTRADO     : $tp"
        Write-Host "  Subject      : $($c.Subject)"
        Write-Host "  HasPrivateKey: $($c.HasPrivateKey)"
        Write-Host "  Vence em     : $($c.NotAfter)"
        Write-Host "  Valido agora : $((Get-Date) -ge $c.NotBefore -and (Get-Date) -le $c.NotAfter)"
    }
}
Write-Host ''
Write-Host 'IMPORTANTE: o arquivo .cer nao inclui chave privada.'
Write-Host 'Se o certificado de ECD4... estiver ausente ou sem chave privada,'
Write-Host 'use a conta Windows em que a chave foi originalmente criada ou solicite'
Write-Host 'ao responsavel o procedimento autorizado de disponibilizacao da chave.'
Write-Host 'Nao gere novo certificado e nao desative a validacao.'
