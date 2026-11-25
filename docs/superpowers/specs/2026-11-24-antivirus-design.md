# Antivirus Open Source — Design Doc

**Data:** 2026-11-24  
**Autor:** DON

## Objetivo
Criar um antivírus para Windows independente de fabricantes, funcional para uso pessoal, e compartilhável como open source.

## Goals
- Escanear arquivos por hash/assinatura contra base de malwares conhecidos
- Monitorar o filesystem em tempo real (sem driver de kernel)
- Colocar arquivos suspeitos em quarentena
- Interface gráfica simples e clara (WPF)
- Base de assinaturas atualizável via internet
- Integração com IA (Claude API) para análise de arquivos suspeitos
- Código aberto (MIT ou GPL v3)

## Non-goals
- Driver de kernel (minifilter) — fase futura
- Suporte a Linux/macOS — fase futura

## Anti-goals
- Ser tão complexo que ninguém consiga contribuir
- Falsos positivos demais
- Consumir muita RAM/CPU em background

## Stack
| Componente | Tecnologia |
|---|---|
| Linguagem | C# (.NET 8) |
| UI | WPF |
| Banco de assinaturas | SQLite (Microsoft.Data.Sqlite) |
| Monitor filesystem | FileSystemWatcher + ReadDirectoryChangesW |
| Hash | SHA256 nativo do .NET |
| AI Analysis | Claude API (claude-sonnet-4-5) |
| VirusTotal | API pública |
| Licença | MIT |

## Arquitetura
```
Antivirus/
├── src/
│   ├── Antivirus.Core/
│   │   ├── Models/          → ScanResult, ThreatInfo, QuarantineEntry
│   │   ├── Scanner/         → FileScanner, HashAnalyzer
│   │   ├── Monitor/         → RealTimeMonitor
│   │   ├── Quarantine/      → QuarantineManager
│   │   ├── Signatures/      → SignatureDatabase, SignatureUpdater
│   │   └── AI/              → ClaudeAnalyzer (Claude API)
│   ├── Antivirus.UI/        → WPF MainWindow, ViewModels
│   └── Antivirus.Tests/     → xUnit tests
└── docs/
```

## Fases
| Fase | Entrega |
|---|---|
| v0.1 | Scanner manual + base de hashes + quarentena |
| v0.2 | Monitor em tempo real |
| v0.3 | UI gráfica WPF completa |
| v0.4 | Atualização automática de assinaturas |
| v0.5 | Análise por IA (Claude API) |
