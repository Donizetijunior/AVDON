# Antivirus Open Source — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Construir a arquitetura base de um antivírus open source para Windows em C# .NET 8, com scanner, quarentena, monitor em tempo real e integração com Claude API.

**Architecture:** Solução .NET 8 com três projetos (Core, UI, Tests). Core contém toda a lógica de detecção via SHA256, monitoramento via FileSystemWatcher, quarentena em pasta isolada, banco de assinaturas SQLite, e análise de IA via Claude API. UI é WPF com MVVM.

**Tech Stack:** C# .NET 8, WPF, SQLite (Microsoft.Data.Sqlite), xUnit, Anthropic SDK (Anthropic.SDK), SHA256 nativo.

**Spec:** `docs/superpowers/specs/2026-11-24-antivirus-design.md`

## Global Constraints
- Target: .NET 8, Windows only
- Linguagem: C# 12
- Testes: xUnit 2.x
- Banco: SQLite via Microsoft.Data.Sqlite 8.x
- Claude API: Anthropic.SDK — modelo `claude-sonnet-4-5`
- Sem driver de kernel nesta fase
- Todos os paths de quarentena ficam em `%APPDATA%\AntivirusOS\Quarantine`

## Review Focus
- Arquivo movido para quarentena mas original não deletado → QuarantineManager deve deletar o original após mover com sucesso
- FileSystemWatcher perde eventos em pastas com volume alto de mudanças → usar `InternalBufferSize = 65536` e tratar `Error` event
- Hash de arquivo em uso (locked) lança IOException → HashAnalyzer deve retornar null e logar, não lançar
- Assinatura duplicada no banco dispara unique constraint → SignatureDatabase.Add deve usar INSERT OR IGNORE
- Claude API offline ou sem chave → ClaudeAnalyzer deve retornar AnalysisResult com IsAvailable=false sem lançar exceção

---

## Task 1: Scaffolding da Solução

**Files:**
- Create: `Antivirus.sln`
- Create: `src/Antivirus.Core/Antivirus.Core.csproj`
- Create: `src/Antivirus.UI/Antivirus.UI.csproj`
- Create: `src/Antivirus.Tests/Antivirus.Tests.csproj`
- Create: `.gitignore`
- Create: `README.md`

**Interfaces:**
- Produces: solução compilável com `dotnet build`

- [ ] **Step 1: Criar solução e projetos**

```bash
cd C:\Users\DON\Antivirus
dotnet new sln -n Antivirus
dotnet new classlib -n Antivirus.Core -o src/Antivirus.Core --framework net8.0
dotnet new wpf -n Antivirus.UI -o src/Antivirus.UI --framework net8.0-windows
dotnet new xunit -n Antivirus.Tests -o src/Antivirus.Tests --framework net8.0
dotnet sln add src/Antivirus.Core src/Antivirus.UI src/Antivirus.Tests
```

- [ ] **Step 2: Adicionar dependências**

```bash
dotnet add src/Antivirus.Core package Microsoft.Data.Sqlite --version 8.0.0
dotnet add src/Antivirus.Core package Anthropic.SDK --version 3.7.0
dotnet add src/Antivirus.UI package CommunityToolkit.Mvvm --version 8.3.2
dotnet add src/Antivirus.UI reference src/Antivirus.Core
dotnet add src/Antivirus.Tests reference src/Antivirus.Core
dotnet add src/Antivirus.Tests package Moq --version 4.20.72
```

- [ ] **Step 3: Verificar build limpo**

```bash
dotnet build
```
Expected: Build succeeded, 0 erros.

- [ ] **Step 4: Commit**

```bash
git init
git add .
git commit -m "feat: scaffold solução Antivirus.sln com Core, UI e Tests"
```

---

## Task 2: Models — Tipos Base

**Files:**
- Create: `src/Antivirus.Core/Models/ThreatLevel.cs`
- Create: `src/Antivirus.Core/Models/ThreatInfo.cs`
- Create: `src/Antivirus.Core/Models/ScanResult.cs`
- Create: `src/Antivirus.Core/Models/QuarantineEntry.cs`
- Test: `src/Antivirus.Tests/Models/ScanResultTests.cs`

**Interfaces:**
- Produces:
  - `enum ThreatLevel { Clean, Suspicious, Malicious }`
  - `record ThreatInfo(string Hash, string Name, ThreatLevel Level, string Description)`
  - `record ScanResult(string FilePath, string Hash, ThreatLevel Level, ThreatInfo? Threat, DateTime ScannedAt)`
  - `record QuarantineEntry(string OriginalPath, string QuarantinePath, string Hash, DateTime QuarantinedAt)`

- [ ] **Step 1: Escrever teste dos models**

```csharp
// ScanResultTests.cs
[Fact]
public void ScanResult_Clean_HasNullThreat()
{
    var r = new ScanResult("C:\\file.exe", "abc123", ThreatLevel.Clean, null, DateTime.UtcNow);
    Assert.Null(r.Threat);
    Assert.Equal(ThreatLevel.Clean, r.Level);
}

[Fact]
public void ScanResult_Malicious_HasThreatInfo()
{
    var threat = new ThreatInfo("abc123", "Trojan.GenericKD", ThreatLevel.Malicious, "Known trojan");
    var r = new ScanResult("C:\\evil.exe", "abc123", ThreatLevel.Malicious, threat, DateTime.UtcNow);
    Assert.NotNull(r.Threat);
    Assert.Equal("Trojan.GenericKD", r.Threat.Name);
}
```

- [ ] **Step 2: Implementar os 4 tipos em seus arquivos**

Records imutáveis em `src/Antivirus.Core/Models/`. Namespace: `AntivirusOS.Core.Models`.

- [ ] **Step 3: Rodar testes**

```bash
dotnet test src/Antivirus.Tests
```
Expected: 2 passed.

- [ ] **Step 4: Commit**

```bash
git add src/Antivirus.Core/Models src/Antivirus.Tests/Models
git commit -m "feat: adicionar models ThreatInfo, ScanResult, QuarantineEntry"
```

---

## Task 3: SignatureDatabase — SQLite

**Files:**
- Create: `src/Antivirus.Core/Signatures/SignatureDatabase.cs`
- Create: `src/Antivirus.Core/Signatures/ISignatureDatabase.cs`
- Test: `src/Antivirus.Tests/Signatures/SignatureDatabaseTests.cs`

**Interfaces:**
- Consumes: `ThreatInfo` (Task 2)
- Produces:
  - `interface ISignatureDatabase`
    - `Task InitializeAsync()`
    - `Task AddSignatureAsync(ThreatInfo threat)`
    - `Task<ThreatInfo?> LookupAsync(string sha256Hash)`
    - `Task<int> CountAsync()`

- [ ] **Step 1: Escrever testes**

```csharp
[Fact]
public async Task Lookup_ExistingHash_ReturnsThreat()
{
    var db = new SignatureDatabase(":memory:");
    await db.InitializeAsync();
    var threat = new ThreatInfo("deadbeef", "Trojan.Test", ThreatLevel.Malicious, "test");
    await db.AddSignatureAsync(threat);
    var result = await db.LookupAsync("deadbeef");
    Assert.NotNull(result);
    Assert.Equal("Trojan.Test", result.Name);
}

[Fact]
public async Task Lookup_UnknownHash_ReturnsNull()
{
    var db = new SignatureDatabase(":memory:");
    await db.InitializeAsync();
    var result = await db.LookupAsync("unknown");
    Assert.Null(result);
}

[Fact]
public async Task AddSignature_Duplicate_DoesNotThrow()
{
    var db = new SignatureDatabase(":memory:");
    await db.InitializeAsync();
    var threat = new ThreatInfo("aabb", "Test", ThreatLevel.Suspicious, "");
    await db.AddSignatureAsync(threat);
    await db.AddSignatureAsync(threat); // INSERT OR IGNORE — sem exceção
}
```

- [ ] **Step 2: Implementar SignatureDatabase**

Tabela `signatures (hash TEXT PRIMARY KEY, name TEXT, level INTEGER, description TEXT)`.  
`InitializeAsync` cria tabela se não existir.  
`AddSignatureAsync` usa `INSERT OR IGNORE`.  
`LookupAsync` retorna null se não encontrar.  
Construtor aceita `string connectionString` (`:memory:` para testes, path real em produção).

- [ ] **Step 3: Rodar testes**

```bash
dotnet test src/Antivirus.Tests --filter "SignatureDatabase"
```
Expected: 3 passed.

- [ ] **Step 4: Commit**

```bash
git add src/Antivirus.Core/Signatures src/Antivirus.Tests/Signatures
git commit -m "feat: SignatureDatabase com SQLite e INSERT OR IGNORE"
```

---

## Task 4: HashAnalyzer — SHA256 de Arquivos

**Files:**
- Create: `src/Antivirus.Core/Scanner/HashAnalyzer.cs`
- Create: `src/Antivirus.Core/Scanner/IHashAnalyzer.cs`
- Test: `src/Antivirus.Tests/Scanner/HashAnalyzerTests.cs`

**Interfaces:**
- Produces:
  - `interface IHashAnalyzer`
    - `Task<string?> ComputeAsync(string filePath)` — retorna null se arquivo locked/inexistente

- [ ] **Step 1: Criar arquivo de teste temporário e escrever testes**

```csharp
[Fact]
public async Task Compute_ValidFile_ReturnsSha256Hex()
{
    var path = Path.GetTempFileName();
    await File.WriteAllTextAsync(path, "hello");
    var analyzer = new HashAnalyzer();
    var hash = await analyzer.ComputeAsync(path);
    Assert.NotNull(hash);
    Assert.Equal(64, hash.Length); // SHA256 hex = 64 chars
    File.Delete(path);
}

[Fact]
public async Task Compute_NonExistentFile_ReturnsNull()
{
    var analyzer = new HashAnalyzer();
    var hash = await analyzer.ComputeAsync("C:\\does_not_exist_xyz.exe");
    Assert.Null(hash);
}
```

- [ ] **Step 2: Implementar HashAnalyzer**

Usar `SHA256.HashDataAsync` (.NET 8). Capturar `IOException` e `UnauthorizedAccessException`, retornar null. Abrir arquivo com `FileShare.Read`.

- [ ] **Step 3: Rodar testes**

```bash
dotnet test src/Antivirus.Tests --filter "HashAnalyzer"
```
Expected: 2 passed.

- [ ] **Step 4: Commit**

```bash
git add src/Antivirus.Core/Scanner src/Antivirus.Tests/Scanner
git commit -m "feat: HashAnalyzer com SHA256 e tratamento de arquivo locked"
```

---

## Task 5: FileScanner — Scanner Manual

**Files:**
- Create: `src/Antivirus.Core/Scanner/FileScanner.cs`
- Create: `src/Antivirus.Core/Scanner/IFileScanner.cs`
- Test: `src/Antivirus.Tests/Scanner/FileScannerTests.cs`

**Interfaces:**
- Consumes: `IHashAnalyzer` (Task 4), `ISignatureDatabase` (Task 3), `ScanResult`, `ThreatInfo` (Task 2)
- Produces:
  - `interface IFileScanner`
    - `Task<ScanResult> ScanFileAsync(string filePath)`
    - `IAsyncEnumerable<ScanResult> ScanDirectoryAsync(string dirPath, bool recursive = true)`

- [ ] **Step 1: Escrever testes com mocks**

```csharp
[Fact]
public async Task ScanFile_KnownMalicious_ReturnsMaliciousResult()
{
    var hashMock = new Mock<IHashAnalyzer>();
    hashMock.Setup(h => h.ComputeAsync(It.IsAny<string>())).ReturnsAsync("deadbeef");
    var dbMock = new Mock<ISignatureDatabase>();
    var threat = new ThreatInfo("deadbeef", "Trojan.Test", ThreatLevel.Malicious, "test");
    dbMock.Setup(d => d.LookupAsync("deadbeef")).ReturnsAsync(threat);

    var scanner = new FileScanner(hashMock.Object, dbMock.Object);
    var result = await scanner.ScanFileAsync("C:\\evil.exe");

    Assert.Equal(ThreatLevel.Malicious, result.Level);
    Assert.NotNull(result.Threat);
}

[Fact]
public async Task ScanFile_UnknownHash_ReturnsClean()
{
    var hashMock = new Mock<IHashAnalyzer>();
    hashMock.Setup(h => h.ComputeAsync(It.IsAny<string>())).ReturnsAsync("aabbcc");
    var dbMock = new Mock<ISignatureDatabase>();
    dbMock.Setup(d => d.LookupAsync("aabbcc")).ReturnsAsync((ThreatInfo?)null);

    var scanner = new FileScanner(hashMock.Object, dbMock.Object);
    var result = await scanner.ScanFileAsync("C:\\clean.exe");

    Assert.Equal(ThreatLevel.Clean, result.Level);
}
```

- [ ] **Step 2: Implementar FileScanner**

`ScanFileAsync`: chama `IHashAnalyzer.ComputeAsync`, depois `ISignatureDatabase.LookupAsync`, monta `ScanResult`.  
`ScanDirectoryAsync`: usa `Directory.EnumerateFiles` com `SearchOption.AllDirectories` se recursive=true, `yield return` cada ScanResult via `await foreach`.

- [ ] **Step 3: Rodar testes**

```bash
dotnet test src/Antivirus.Tests --filter "FileScanner"
```
Expected: 2 passed.

- [ ] **Step 4: Commit**

```bash
git add src/Antivirus.Core/Scanner src/Antivirus.Tests/Scanner
git commit -m "feat: FileScanner com scan por arquivo e diretório"
```

---

## Task 6: QuarantineManager

**Files:**
- Create: `src/Antivirus.Core/Quarantine/QuarantineManager.cs`
- Create: `src/Antivirus.Core/Quarantine/IQuarantineManager.cs`
- Test: `src/Antivirus.Tests/Quarantine/QuarantineManagerTests.cs`

**Interfaces:**
- Consumes: `QuarantineEntry` (Task 2)
- Produces:
  - `interface IQuarantineManager`
    - `Task<QuarantineEntry> QuarantineAsync(string filePath, string hash)`
    - `Task RestoreAsync(QuarantineEntry entry)`
    - `Task DeleteAsync(QuarantineEntry entry)`
    - `Task<IReadOnlyList<QuarantineEntry>> ListAsync()`

- [ ] **Step 1: Escrever testes**

```csharp
[Fact]
public async Task Quarantine_MovesFileAndDeletesOriginal()
{
    var tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
    var manager = new QuarantineManager(tempDir);
    var original = Path.GetTempFileName();
    await File.WriteAllTextAsync(original, "malware");

    var entry = await manager.QuarantineAsync(original, "aabbcc");

    Assert.False(File.Exists(original));
    Assert.True(File.Exists(entry.QuarantinePath));
    Directory.Delete(tempDir, true);
}
```

- [ ] **Step 2: Implementar QuarantineManager**

Pasta de quarentena: injetada via construtor (default: `%APPDATA%\AntivirusOS\Quarantine`).  
`QuarantineAsync`: move arquivo para quarentena com nome `{hash}_{timestamp}.quar`, deleta original, persiste `QuarantineEntry` em JSON local (`quarantine.json` na pasta de quarentena).  
`ListAsync`: lê o `quarantine.json`.  
`RestoreAsync`: move de volta para `OriginalPath`.  
`DeleteAsync`: deleta o arquivo em quarentena e remove do JSON.

- [ ] **Step 3: Rodar testes**

```bash
dotnet test src/Antivirus.Tests --filter "QuarantineManager"
```
Expected: 1 passed.

- [ ] **Step 4: Commit**

```bash
git add src/Antivirus.Core/Quarantine src/Antivirus.Tests/Quarantine
git commit -m "feat: QuarantineManager isola e restaura arquivos suspeitos"
```

---

## Task 7: RealTimeMonitor — FileSystemWatcher

**Files:**
- Create: `src/Antivirus.Core/Monitor/RealTimeMonitor.cs`
- Create: `src/Antivirus.Core/Monitor/IRealTimeMonitor.cs`
- Create: `src/Antivirus.Core/Monitor/FileDetectedEventArgs.cs`
- Test: `src/Antivirus.Tests/Monitor/RealTimeMonitorTests.cs`

**Interfaces:**
- Consumes: `IFileScanner` (Task 5), `IQuarantineManager` (Task 6)
- Produces:
  - `interface IRealTimeMonitor`
    - `void StartMonitoring(string path)`
    - `void StopMonitoring()`
    - `event EventHandler<FileDetectedEventArgs> ThreatDetected`
  - `record FileDetectedEventArgs(ScanResult Result)`

- [ ] **Step 1: Escrever teste de integração**

```csharp
[Fact]
public async Task Monitor_DetectsNewFile_RaisesThreatDetected()
{
    // Arrange: mock scanner que retorna Malicious
    var scannerMock = new Mock<IFileScanner>();
    var threat = new ThreatInfo("xx", "T", ThreatLevel.Malicious, "");
    scannerMock.Setup(s => s.ScanFileAsync(It.IsAny<string>()))
        .ReturnsAsync(new ScanResult("", "xx", ThreatLevel.Malicious, threat, DateTime.UtcNow));
    var quarMock = new Mock<IQuarantineManager>();
    quarMock.Setup(q => q.QuarantineAsync(It.IsAny<string>(), It.IsAny<string>()))
        .ReturnsAsync(new QuarantineEntry("", "", "", DateTime.UtcNow));

    var monitor = new RealTimeMonitor(scannerMock.Object, quarMock.Object);
    var tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
    Directory.CreateDirectory(tempDir);

    FileDetectedEventArgs? detected = null;
    monitor.ThreatDetected += (_, e) => detected = e;
    monitor.StartMonitoring(tempDir);

    // Act
    await File.WriteAllTextAsync(Path.Combine(tempDir, "test.exe"), "data");
    await Task.Delay(500); // aguarda evento

    // Assert
    Assert.NotNull(detected);
    monitor.StopMonitoring();
    Directory.Delete(tempDir, true);
}
```

- [ ] **Step 2: Implementar RealTimeMonitor**

`FileSystemWatcher` com `InternalBufferSize = 65536`.  
Monitorar `Created` e `Changed`.  
Handler chama `IFileScanner.ScanFileAsync`; se `Level != Clean` chama `IQuarantineManager.QuarantineAsync` e dispara `ThreatDetected`.  
Tratar evento `Error` logando no `Debug`.  
`StopMonitoring` faz `Dispose` do watcher.

- [ ] **Step 3: Rodar testes**

```bash
dotnet test src/Antivirus.Tests --filter "RealTimeMonitor"
```
Expected: 1 passed.

- [ ] **Step 4: Commit**

```bash
git add src/Antivirus.Core/Monitor src/Antivirus.Tests/Monitor
git commit -m "feat: RealTimeMonitor com FileSystemWatcher e auto-quarentena"
```

---

## Task 8: ClaudeAnalyzer — IA para Arquivos Suspeitos

**Files:**
- Create: `src/Antivirus.Core/AI/ClaudeAnalyzer.cs`
- Create: `src/Antivirus.Core/AI/IClaudeAnalyzer.cs`
- Create: `src/Antivirus.Core/AI/AnalysisResult.cs`
- Test: `src/Antivirus.Tests/AI/ClaudeAnalyzerTests.cs`

**Interfaces:**
- Produces:
  - `record AnalysisResult(bool IsAvailable, bool IsSuspicious, string Reasoning, ThreatLevel SuggestedLevel)`
  - `interface IClaudeAnalyzer`
    - `Task<AnalysisResult> AnalyzeFileAsync(string filePath, string hash)`

- [ ] **Step 1: Escrever testes (sem chamar API real)**

```csharp
[Fact]
public async Task Analyze_NoApiKey_ReturnsUnavailable()
{
    var analyzer = new ClaudeAnalyzer(apiKey: "");
    var result = await analyzer.AnalyzeFileAsync("C:\\file.exe", "abc");
    Assert.False(result.IsAvailable);
}
```

- [ ] **Step 2: Implementar ClaudeAnalyzer**

Usar `Anthropic.SDK`. Se `apiKey` vazio ou nulo → retornar `AnalysisResult(false, false, "API key not configured", ThreatLevel.Clean)`.  
Prompt ao Claude: enviar nome do arquivo, hash SHA256, e primeiros 512 bytes em base64 se arquivo < 10MB, pedindo análise de risco em JSON: `{isSuspicious: bool, reasoning: string, level: "Clean"|"Suspicious"|"Malicious"}`.  
Parsear resposta JSON. Em caso de exceção de rede → retornar `IsAvailable=false`.  
Modelo: `claude-sonnet-4-5`.

- [ ] **Step 3: Rodar testes**

```bash
dotnet test src/Antivirus.Tests --filter "ClaudeAnalyzer"
```
Expected: 1 passed.

- [ ] **Step 4: Commit**

```bash
git add src/Antivirus.Core/AI src/Antivirus.Tests/AI
git commit -m "feat: ClaudeAnalyzer integra Claude API para análise de arquivos suspeitos"
```

---

## Task 9: SignatureUpdater — Download de Assinaturas

**Files:**
- Create: `src/Antivirus.Core/Signatures/SignatureUpdater.cs`
- Create: `src/Antivirus.Core/Signatures/ISignatureUpdater.cs`

**Interfaces:**
- Consumes: `ISignatureDatabase` (Task 3)
- Produces:
  - `interface ISignatureUpdater`
    - `Task<int> UpdateFromMalwareBazaarAsync()` — retorna número de assinaturas adicionadas

- [ ] **Step 1: Implementar SignatureUpdater**

Baixar CSV público do MalwareBazaar (`https://bazaar.abuse.ch/export/csv/full/`) via `HttpClient`.  
Parsear linhas (ignorar comentários `#`), extrair coluna `sha256_hash` e `signature`.  
Chamar `ISignatureDatabase.AddSignatureAsync` para cada linha válida.  
Sem testes automatizados nesta task (rede externa) — testar manualmente.

- [ ] **Step 2: Commit**

```bash
git add src/Antivirus.Core/Signatures/SignatureUpdater.cs
git commit -m "feat: SignatureUpdater baixa assinaturas do MalwareBazaar"
```

---

## Task 10: UI WPF — MainWindow e ViewModel

**Files:**
- Create: `src/Antivirus.UI/ViewModels/MainViewModel.cs`
- Modify: `src/Antivirus.UI/MainWindow.xaml`
- Modify: `src/Antivirus.UI/MainWindow.xaml.cs`
- Create: `src/Antivirus.UI/App.xaml.cs` (DI setup)

**Interfaces:**
- Consumes: todos os serviços Core (Tasks 3-8)
- Produces: aplicação WPF executável com as 4 abas abaixo

- [ ] **Step 1: Implementar MainViewModel com CommunityToolkit.Mvvm**

Propriedades observáveis: `ScanStatus`, `ScanResults (ObservableCollection<ScanResult>)`, `QuarantineEntries (ObservableCollection<QuarantineEntry>)`, `IsMonitoring`.  
Comandos: `ScanFileCommand`, `ScanFolderCommand`, `ToggleMonitorCommand`, `UpdateSignaturesCommand`.

- [ ] **Step 2: Criar layout MainWindow.xaml**

4 abas (TabControl):
1. **Scan** — botões "Escanear Arquivo" e "Escanear Pasta", lista de resultados com ícone de status
2. **Proteção em Tempo Real** — toggle on/off, caminho monitorado, log de eventos
3. **Quarentena** — lista de arquivos isolados com botões Restaurar e Deletar
4. **Configurações** — campo para Claude API Key, botão Atualizar Assinaturas, contagem de assinaturas

- [ ] **Step 3: Configurar DI em App.xaml.cs**

Registrar via `Microsoft.Extensions.DependencyInjection`:  
`ISignatureDatabase` → `SignatureDatabase` (path: `%APPDATA%\AntivirusOS\signatures.db`)  
`IHashAnalyzer` → `HashAnalyzer`  
`IFileScanner` → `FileScanner`  
`IQuarantineManager` → `QuarantineManager`  
`IRealTimeMonitor` → `RealTimeMonitor`  
`IClaudeAnalyzer` → `ClaudeAnalyzer` (ler API key de settings)  
`MainViewModel` como singleton

- [ ] **Step 4: Testar manualmente**

Iniciar app, escanear um arquivo limpo, escanear o próprio executável, verificar todas as abas.

- [ ] **Step 5: Commit**

```bash
git add src/Antivirus.UI
git commit -m "feat: UI WPF completa com 4 abas e injeção de dependência"
```

---

## Resumo de Commits Esperados
1. `feat: scaffold solução`
2. `feat: models base`
3. `feat: SignatureDatabase SQLite`
4. `feat: HashAnalyzer SHA256`
5. `feat: FileScanner`
6. `feat: QuarantineManager`
7. `feat: RealTimeMonitor`
8. `feat: ClaudeAnalyzer IA`
9. `feat: SignatureUpdater MalwareBazaar`
10. `feat: UI WPF`
