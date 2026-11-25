# AntivirusOS

Antivírus open source para Windows, independente de fabricantes.

## Stack
- C# .NET 8 / WPF
- SQLite (assinaturas de malware)
- Claude API (análise por IA)
- MalwareBazaar (base de hashes)

## Projetos
| Projeto | Descrição |
|---|---|
| `Antivirus.Core` | Motor: scanner, quarentena, monitor, IA |
| `Antivirus.UI` | Interface WPF |
| `Antivirus.Tests` | Testes xUnit |

## Build

```powershell
dotnet build
dotnet test
```

## Licença
MIT
