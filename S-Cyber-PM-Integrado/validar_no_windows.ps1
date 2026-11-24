# ==============================================================================
#  S-Cyber 2.0 (desenvolvimento) - validacao no Windows da propria maquina
# ------------------------------------------------------------------------------
#  Roda os testes, gera o executavel e o instalador, instala por usuario, abre o
#  programa INSTALADO em modo diagnostico e mede os tempos. Nada vai para a
#  internet alem das bibliotecas (pip) e da consulta real as fontes publicas
#  usada pelos testes. Nada e enviado ao GitHub.
#
#  Como usar (Windows PowerShell, na pasta S-Cyber-PM-Integrado):
#     powershell -ExecutionPolicy Bypass -File .\validar_no_windows.ps1
#  Opcoes:  -Desinstalar  (testa tambem a desinstalacao no final)
#           -SemTestes    (pula a suite de testes)
#
#  Resultado: pasta validacao_scyber_<data> na Area de Trabalho, com
#  RESULTADO.txt (envie este arquivo) e os logs de cada etapa.
# ==============================================================================
param([switch]$Desinstalar, [switch]$SemTestes)
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
$env:PYTHONUTF8 = '1'; $env:PYTHONIOENCODING = 'utf-8'
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch { }
$saida = Join-Path ([Environment]::GetFolderPath('Desktop')) ('validacao_scyber_{0:yyyyMMdd_HHmm}' -f (Get-Date))
New-Item -ItemType Directory -Force $saida | Out-Null
$r = [ordered]@{}
$etapas = New-Object System.Collections.ArrayList

function Etapa($nome, [scriptblock]$bloco) {
  Write-Host "`n== $nome" -ForegroundColor Cyan
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $ok = $true; $msg = ''
  try { & $bloco | Out-Null } catch { $ok = $false; $msg = $_.Exception.Message; Write-Host "FALHOU: $msg" -ForegroundColor Red }
  $sw.Stop()
  [void]$etapas.Add([ordered]@{ etapa = $nome; ok = $ok; segundos = [math]::Round($sw.Elapsed.TotalSeconds, 1); detalhe = $msg })
  return $ok
}

# Roda um programa externo gravando stdout+stderr no log e devolve o codigo de
# saida. No Windows PowerShell 5.1, com ErrorActionPreference=Stop, a primeira
# linha que um programa escreve no stderr (unittest e PyInstaller escrevem o
# progresso normal ali) vira excecao e interrompe a etapa. Aqui o stderr e
# apenas texto; quem decide se falhou e o codigo de saida.
function Rodar([string]$log, [string]$exe, [string[]]$argumentos, [switch]$Anexar) {
  $ErrorActionPreference = 'Continue'
  $texto = & $exe @argumentos 2>&1 | ForEach-Object {
    if ($_ -is [Management.Automation.ErrorRecord]) {
      $m = $_.Exception.Message                  # linha vazia do stderr chega como 'RemoteException'
      if ($m -eq 'System.Management.Automation.RemoteException') { '' } else { $m }
    } else { "$_" }
  }
  $codigo = $LASTEXITCODE
  if ($Anexar) { $texto | Add-Content $log -Encoding UTF8 } else { $texto | Set-Content $log -Encoding UTF8 }
  return $codigo
}

$py = Join-Path $PSScriptRoot '.venv-build\Scripts\python.exe'

Etapa 'Ambiente' {
  $os = Get-CimInstance Win32_OperatingSystem
  $cpu = (Get-CimInstance Win32_Processor | Select-Object -First 1).Name
  $r.windows = "$($os.Caption) $($os.Version) ($($os.OSArchitecture))"
  $r.processador = $cpu
  $r.memoria_gb = [math]::Round($os.TotalVisibleMemorySize / 1MB, 1)
  $r.python_sistema = (& py -3 --version) 2>&1
  $r.commit = '(sem git: copia do zip)'
  if (Get-Command git -ErrorAction SilentlyContinue) {
    $c = (& git rev-parse --short HEAD 2>$null); if ($c) { $r.commit = $c }
  }
} | Out-Null

$depsOk = Etapa 'Ambiente Python isolado (.venv-build) com as versoes travadas' {
  if (-not (Test-Path $py)) { & py -3 -m venv .venv-build; if ($LASTEXITCODE) { throw 'venv falhou' } }
  $log = Join-Path $saida 'pip.txt'
  if (Rodar $log $py @('-m','pip','install','--disable-pip-version-check','-q','-r','requirements-lock.txt')) { throw 'pip install -r requirements-lock.txt falhou (veja pip.txt)' }
  if (Rodar $log $py @('-m','pip','install','--disable-pip-version-check','-q','pyinstaller') -Anexar) { throw 'pip install pyinstaller falhou (veja pip.txt)' }
  & $py -m pip freeze | Set-Content (Join-Path $saida 'pip_freeze.txt')
  $r.python_build = (& $py --version) 2>&1
}

if ($depsOk -and -not $SemTestes) {
  Etapa 'Testes automaticos (inclui consulta real as fontes publicas)' {
    $env:SCYBER_FONTES_REAIS = '1'
    $codigo = Rodar (Join-Path $saida 'testes.txt') $py @('-m','unittest','discover','-s','tests','-v')
    # stdout e stderr chegam fora de ordem: procura no arquivo inteiro, nao so no fim
    $r.testes = (Get-Content (Join-Path $saida 'testes.txt') | Where-Object { $_ -match '^(Ran \d|OK|FAILED)' }) -join ' | '
    if ($codigo) { throw "testes com falha: $($r.testes) (veja testes.txt)" }
  } | Out-Null
}

$exeOk = $depsOk -and (Etapa 'Executavel (PyInstaller)' {
  $codigo = Rodar (Join-Path $saida 'build_exe.txt') $py @('gerarExe.py')
  if ($codigo -or -not (Test-Path 'dist\SCyberPM.exe')) { throw "gerarExe.py falhou com codigo $codigo (veja build_exe.txt)" }
  $r.exe_mb = [math]::Round((Get-Item 'dist\SCyberPM.exe').Length / 1MB, 1)
})

$iscc = "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe"
if (-not (Test-Path $iscc)) { $iscc = "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe" }
$setupOk = $false
if ($exeOk) {
  if (-not (Test-Path $iscc)) {
    [void]$etapas.Add([ordered]@{ etapa = 'Instalador (Inno Setup)'; ok = $false; segundos = 0;
      detalhe = 'Inno Setup 6 nao encontrado. Instale com: winget install JRSoftware.InnoSetup  e rode de novo.' })
  } else {
    $setupOk = Etapa 'Instalador (Inno Setup)' {
      $versao = & $py -c "from formAbout import APP_VERSAO; print(APP_VERSAO)"
      if (Rodar (Join-Path $saida 'build_instalador.txt') $iscc @("/DAppVersion=$versao", 'instalador\SCyberPM.iss')) { throw 'ISCC falhou (veja build_instalador.txt)' }
      $script:setup = (Get-Item "dist\SCyberPM-Setup-$versao.exe").FullName
      $r.instalador_mb = [math]::Round((Get-Item $script:setup).Length / 1MB, 1)
      $r.versao = $versao
    }
  }
}

$exeInst = Join-Path $env:LOCALAPPDATA 'Programs\S-Cyber PM\SCyberPM.exe'
if ($setupOk) {
  $instOk = Etapa 'Instalacao silenciosa por usuario' {
    # Com o programa aberto o instalador nao consegue trocar o .exe, desfaz tudo e sai com 5
    $abertos = @(Get-Process -Name SCyberPM -ErrorAction SilentlyContinue)
    if ($abertos.Count) { throw "o S-Cyber PM esta ABERTO (PID $($abertos.Id -join ', ')). Feche-o e rode o script de novo." }
    $p = Start-Process $script:setup -ArgumentList '/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/CURRENTUSER',"/LOG=$saida\instalacao.log" -Wait -PassThru
    if ($p.ExitCode) { throw "instalador saiu com $($p.ExitCode)" }
    if (-not (Test-Path $exeInst)) { throw "nao instalou em $exeInst" }
  }
  # Sem instalar a versao nova, medir o programa instalado seria medir a versao ANTIGA
  if ($instOk) { Etapa 'Programa instalado: diagnostico de abertura (3 vezes)' {
    $tempos = @()
    foreach ($i in 1..3) {
      $arq = Join-Path $saida "diagnostico_$i.txt"
      $sw = [Diagnostics.Stopwatch]::StartNew()
      Start-Process $exeInst -ArgumentList '--diagnostico', $arq, '--sem-perfil' -Wait
      $sw.Stop(); $tempos += $sw.Elapsed.TotalSeconds
      if (-not (Test-Path $arq)) { throw 'o executavel instalado nao gerou o diagnostico' }
    }
    $r.diagnostico_s = (($tempos | ForEach-Object { [math]::Round($_, 2) }) -join ' / ')
    $txt = Get-Content (Join-Path $saida 'diagnostico_1.txt') -Raw -Encoding UTF8
    $r.diagnostico_resumo = (($txt -split "`n") | Where-Object { $_ -match '^(Vers|Ativa|Certificados em|PR)' }) -join ' | '
  } | Out-Null }
  if ($instOk -and $Desinstalar) {
    Etapa 'Desinstalacao (dados do usuario devem ficar)' {
      $unins = Get-ChildItem (Split-Path $exeInst) -Filter 'unins*.exe' | Select-Object -First 1
      Start-Process $unins.FullName -ArgumentList '/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART' -Wait
      Start-Sleep 3
      if (Test-Path $exeInst) { throw 'o executavel continuou instalado' }
      $r.dados_preservados = Test-Path (Join-Path $env:APPDATA 'SCyberPM')
    } | Out-Null
  }
}

foreach ($f in @('dist\SCyberPM.exe', $script:setup)) {
  if ($f -and (Test-Path $f)) { $r["sha256_$(Split-Path $f -Leaf)"] = (Get-FileHash $f -Algorithm SHA256).Hash.ToLower() }
}

$linhas = @('S-Cyber 2.0 (desenvolvimento) - validacao no Windows', ('Data: {0:dd/MM/yyyy HH:mm}' -f (Get-Date)), '')
foreach ($k in $r.Keys) { $linhas += ('{0,-22}: {1}' -f $k, $r[$k]) }
$linhas += '', 'ETAPAS'
foreach ($e in $etapas) { $linhas += ('  [{0}] {1} ({2} s) {3}' -f ($(if ($e.ok) { 'OK' } else { 'FALHA' })), $e.etapa, $e.segundos, $e.detalhe) }
$linhas += '', 'TESTE MANUAL (pela interface, abrindo pelo atalho do menu Iniciar):',
  '  1. Abre a tela de ATIVACAO; Copiar pedido funciona.',
  '  2. Depois de ativar: perfil novo vai direto para CRIAR AS SENHAS (nao existe senha de fabrica).',
  '  3. Licenca vencida/revogada: botao "Recuperar meus dados" exporta backup + CSV + MANIFESTO.',
  '  4. Ativos e achados: usuario comum NAO consegue Aprovar; revisor consegue (papel do certificado).'
$linhas | Set-Content (Join-Path $saida 'RESULTADO.txt') -Encoding UTF8
$r | ConvertTo-Json | Set-Content (Join-Path $saida 'resultado.json') -Encoding UTF8
Write-Host "`nPronto. Envie: $saida\RESULTADO.txt" -ForegroundColor Green
