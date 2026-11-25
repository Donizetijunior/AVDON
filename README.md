# AVDON — Antivírus Open Source para Windows

Antivírus independente, desenvolvido do zero em C# .NET 8, sem depender de fabricantes comerciais.

## Funcionalidades

### Detecção
| Camada | O que detecta |
|--------|--------------|
| SHA256 + MalwareBazaar | Malware com hash conhecido (centenas de milhares de amostras) |
| YARA rules | Padrões de bytes — inclui regra EICAR e UPX |
| Entropia de arquivo | Arquivos empacotados ou cifrados (entropia > 7.0) |
| Análise estática de PE | Imports suspeitos (`VirtualAllocEx`, `WriteProcessMemory`, etc.) e seções anômalas |
| Scan recursivo de ZIP/RAR/7z | Malware escondido dentro de arquivos comprimidos |
| Authenticode check | Pula automaticamente binários assinados por publishers confiáveis (Microsoft, Google, Adobe) |

### Proteção
- **Monitoramento em tempo real** via FileSystemWatcher com debounce (Channel-based)
- **Quarentena** — isola arquivos suspeitos em `%APPDATA%\AntivirusOS\Quarantine`
- **Restaurar ou deletar** arquivos em quarentena
- **Notificações** nativas do Windows ao detectar ameaça
- **System tray** — roda minimizado como um AV real

### Gestão
- **Histórico de scans** em SQLite (últimos 100 resultados)
- **Cache inteligente** — não re-escaneia arquivo que não mudou (path + tamanho + data)
- **Atualização automática** de assinaturas a cada 24h (MalwareBazaar)
- **Scan agendado** — scan periódico de uma pasta configurável
- **Iniciar com o Windows** — opção na aba Configurações

### IA
- Análise por **Claude AI** (Anthropic) para arquivos suspeitos sem hash conhecido
- Requer API key própria (opcional — o resto funciona sem ela)

## Stack

| Componente | Tecnologia |
|-----------|-----------|
| Linguagem | C# 12 / .NET 8 |
| Interface | WPF + CommunityToolkit.Mvvm |
| Banco de dados | SQLite (Microsoft.Data.Sqlite) |
| IA | Anthropic Claude API (claude-sonnet-4-5) |
| Assinaturas | MalwareBazaar CSV |
| Scan de arquivos comprimidos | SharpCompress |
| DI | Microsoft.Extensions.DependencyInjection |

## Projetos

| Projeto | Descrição |
|---------|-----------|
| `src/Antivirus.Core` | Motor: scanner, quarentena, monitor, IA, updater, cache, histórico |
| `src/Antivirus.UI` | Interface WPF com 5 abas |
| `src/Antivirus.Tests` | 33 testes unitários (xUnit + Moq) |

## Como usar

### Pré-requisitos
- Windows 10/11 x64
- .NET 8 SDK (para build) ou baixar o `AntivirusOS.exe` da [página de Releases](../../releases)

### Executar (desenvolvimento)

```powershell
git clone https://github.com/Donizetijunior/AVDON.git
cd AVDON
dotnet run --project src/Antivirus.UI
```

### Build e testes

```powershell
dotnet build Antivirus.sln
dotnet test src/Antivirus.Tests
```

### Primeira execução
1. Abra o app
2. Vá na aba **Configurações**
3. (Opcional) insira sua API key do Claude para análise por IA
4. Clique em **Atualizar Assinaturas** para baixar do MalwareBazaar
5. Use a aba **Escanear** para fazer seu primeiro scan

## CI/CD

O GitHub Actions executa automaticamente em cada push para `main`:
- Build Release
- 33 testes unitários
- Publicação de `AntivirusOS.exe` self-contained win-x64 na página de Releases

## Licença

MIT © [Donizetijunior](https://github.com/Donizetijunior)
