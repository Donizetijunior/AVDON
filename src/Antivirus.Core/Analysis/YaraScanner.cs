using System.Text;
using System.Text.RegularExpressions;

namespace AntivirusOS.Core.Analysis;

public class YaraScanner : IYaraScanner
{
    private const int MaxBytes = 1024 * 1024; // 1 MB

    private readonly List<YaraRule> _rules = [];

    private record YaraPattern(string Name, byte[]? HexBytes, byte[]? LiteralBytes);
    private record YaraRule(string Name, string Description, List<YaraPattern> Patterns, bool RequireAll);

    public void LoadRules(string rulesDirectory)
    {
        _rules.Clear();
        if (!Directory.Exists(rulesDirectory)) return;

        foreach (var file in Directory.GetFiles(rulesDirectory, "*.yar"))
        {
            try
            {
                var rules = ParseFile(file);
                _rules.AddRange(rules);
            }
            catch { /* skip malformed rule files */ }
        }
    }

    private static List<YaraRule> ParseFile(string filePath)
    {
        var rules = new List<YaraRule>();
        var text = File.ReadAllText(filePath);

        // Match rule blocks: rule Name { ... } — allow nested { } by counting braces
        int pos = 0;
        while (pos < text.Length)
        {
            // Find "rule <name>"
            var ruleKeyword = text.IndexOf("rule ", pos, StringComparison.Ordinal);
            if (ruleKeyword < 0) break;

            // Extract name
            int nameStart = ruleKeyword + 5;
            while (nameStart < text.Length && char.IsWhiteSpace(text[nameStart])) nameStart++;
            int nameEnd = nameStart;
            while (nameEnd < text.Length && (char.IsLetterOrDigit(text[nameEnd]) || text[nameEnd] == '_')) nameEnd++;
            var ruleName = text[nameStart..nameEnd];

            // Find opening brace
            int openBrace = text.IndexOf('{', nameEnd);
            if (openBrace < 0) break;

            // Find matching closing brace
            int depth = 1;
            int i = openBrace + 1;
            while (i < text.Length && depth > 0)
            {
                if (text[i] == '{') depth++;
                else if (text[i] == '}') depth--;
                i++;
            }
            if (depth != 0) break;

            var body = text[(openBrace + 1)..(i - 1)];
            pos = i;

            var rule = ParseRuleBody(ruleName, body);
            if (rule != null) rules.Add(rule);
        }

        return rules;
    }

    private static YaraRule? ParseRuleBody(string ruleName, string body)
    {
        // Extract description from meta section
        var descMatch = Regex.Match(body, @"description\s*=\s*""([^""]*)""");
        var description = descMatch.Success ? descMatch.Groups[1].Value : string.Empty;

        // Extract strings section
        var stringsSection = string.Empty;
        var strStart = body.IndexOf("strings:", StringComparison.Ordinal);
        if (strStart >= 0)
        {
            var condStart = body.IndexOf("condition:", strStart, StringComparison.Ordinal);
            stringsSection = condStart >= 0
                ? body[strStart..condStart]
                : body[strStart..];
        }

        var patterns = new List<YaraPattern>();

        // Parse hex patterns: $name = { XX XX XX }
        foreach (Match m in Regex.Matches(stringsSection, @"\$(\w+)\s*=\s*\{([^}]+)\}"))
        {
            var bytes = ParseHexBytes(m.Groups[2].Value);
            if (bytes != null)
                patterns.Add(new YaraPattern(m.Groups[1].Value, bytes, null));
        }

        // Parse literal string patterns: $name = "..."
        // Use a manual approach to avoid issues with escaped quotes
        int sPos = 0;
        while (sPos < stringsSection.Length)
        {
            var dollarIdx = stringsSection.IndexOf('$', sPos);
            if (dollarIdx < 0) break;

            // Extract var name
            int vEnd = dollarIdx + 1;
            while (vEnd < stringsSection.Length && (char.IsLetterOrDigit(stringsSection[vEnd]) || stringsSection[vEnd] == '_')) vEnd++;

            // Skip whitespace and '='
            int eqPos = vEnd;
            while (eqPos < stringsSection.Length && char.IsWhiteSpace(stringsSection[eqPos])) eqPos++;
            if (eqPos >= stringsSection.Length || stringsSection[eqPos] != '=') { sPos = dollarIdx + 1; continue; }
            eqPos++; // skip '='
            while (eqPos < stringsSection.Length && char.IsWhiteSpace(stringsSection[eqPos])) eqPos++;

            if (eqPos >= stringsSection.Length) break;

            if (stringsSection[eqPos] == '"')
            {
                // Find closing quote (non-escaped)
                int qEnd = eqPos + 1;
                while (qEnd < stringsSection.Length && stringsSection[qEnd] != '"') qEnd++;
                if (qEnd < stringsSection.Length)
                {
                    var literal = stringsSection[(eqPos + 1)..qEnd];
                    patterns.Add(new YaraPattern("$" + stringsSection[dollarIdx..vEnd], null, Encoding.ASCII.GetBytes(literal)));
                    sPos = qEnd + 1;
                    continue;
                }
            }

            sPos = dollarIdx + 1;
        }

        // Extract condition
        var condMatch = Regex.Match(body, @"condition\s*:([\s\S]+?)(?=\}|$)");
        var condition = condMatch.Success ? condMatch.Groups[1].Value.Trim().ToLowerInvariant() : "any of them";
        var requireAll = condition.Contains("all of them");

        return new YaraRule(ruleName, description, patterns, requireAll);
    }

    private static byte[]? ParseHexBytes(string hexStr)
    {
        var tokens = hexStr.Split((char[])[' ', '\t', '\n', '\r'], StringSplitOptions.RemoveEmptyEntries);
        var bytes = new List<byte>();
        foreach (var t in tokens)
        {
            if (t.Length == 2 && byte.TryParse(t, System.Globalization.NumberStyles.HexNumber, null, out var b))
                bytes.Add(b);
        }
        return bytes.Count > 0 ? bytes.ToArray() : null;
    }

    public async Task<List<YaraMatch>> ScanAsync(string filePath)
    {
        var matches = new List<YaraMatch>();
        if (_rules.Count == 0) return matches;

        byte[] data;
        try
        {
            await using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, useAsync: true);
            var size = (int)Math.Min(stream.Length, MaxBytes);
            if (size == 0) return matches;
            data = new byte[size];
            int offset = 0;
            while (offset < size)
            {
                int read = await stream.ReadAsync(data.AsMemory(offset, size - offset));
                if (read == 0) break;
                offset += read;
            }
        }
        catch { return matches; }

        foreach (var rule in _rules)
        {
            if (rule.Patterns.Count == 0) continue;

            var patternResults = new List<bool>();
            foreach (var pattern in rule.Patterns)
            {
                byte[]? needle = pattern.HexBytes ?? pattern.LiteralBytes;
                patternResults.Add(needle != null && ContainsBytes(data, needle));
            }

            bool ruleMatched = rule.RequireAll
                ? patternResults.All(r => r)
                : patternResults.Any(r => r);

            if (ruleMatched)
                matches.Add(new YaraMatch(rule.Name, rule.Description));
        }

        return matches;
    }

    private static bool ContainsBytes(byte[] data, byte[] pattern)
    {
        if (pattern.Length == 0 || data.Length < pattern.Length) return false;
        int limit = data.Length - pattern.Length;
        for (int i = 0; i <= limit; i++)
        {
            bool match = true;
            for (int j = 0; j < pattern.Length; j++)
            {
                if (data[i + j] != pattern[j]) { match = false; break; }
            }
            if (match) return true;
        }
        return false;
    }
}
