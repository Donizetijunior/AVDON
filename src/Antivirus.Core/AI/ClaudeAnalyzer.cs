using System.Text;
using System.Text.Json;
using Anthropic.SDK;
using Anthropic.SDK.Messaging;
using AntivirusOS.Core.Models;

namespace AntivirusOS.Core.AI;

public class ClaudeAnalyzer : IClaudeAnalyzer
{
    private readonly string _apiKey;
    private static readonly AnalysisResult Unavailable =
        new(false, false, "API key not configured", ThreatLevel.Clean);

    public ClaudeAnalyzer(string apiKey)
    {
        _apiKey = apiKey;
    }

    public async Task<AnalysisResult> AnalyzeFileAsync(string filePath, string hash)
    {
        if (string.IsNullOrEmpty(_apiKey))
            return Unavailable;

        try
        {
            var promptBuilder = new StringBuilder();
            promptBuilder.AppendLine($"Analyze this file for security threats:");
            promptBuilder.AppendLine($"File name: {Path.GetFileName(filePath)}");
            promptBuilder.AppendLine($"SHA256 hash: {hash}");

            // Include first 512 bytes if file exists and is < 10MB
            if (File.Exists(filePath))
            {
                var info = new FileInfo(filePath);
                if (info.Length < 10 * 1024 * 1024)
                {
                    using var fs = File.OpenRead(filePath);
                    var buf = new byte[Math.Min(512, info.Length)];
                    var read = await fs.ReadAsync(buf, 0, buf.Length);
                    if (read > 0)
                    {
                        var b64 = Convert.ToBase64String(buf, 0, read);
                        promptBuilder.AppendLine($"First {read} bytes (base64): {b64}");
                    }
                }
            }

            promptBuilder.AppendLine();
            promptBuilder.AppendLine("Respond ONLY with valid JSON in this exact format:");
            promptBuilder.AppendLine("{\"isSuspicious\": bool, \"reasoning\": \"string\", \"level\": \"Clean\"|\"Suspicious\"|\"Malicious\"}");

            var client = new AnthropicClient(new APIAuthentication(_apiKey));
            var request = new MessageParameters
            {
                Model = "claude-sonnet-4-5",
                MaxTokens = 512,
                Messages = new List<Message>
                {
                    new Message { Role = RoleType.User, Content = new List<ContentBase> { new TextContent { Text = promptBuilder.ToString() } } }
                }
            };

            var response = await client.Messages.GetClaudeMessageAsync(request);
            var text = response.Content.OfType<TextContent>().FirstOrDefault()?.Text ?? "";

            // Extract JSON from the response
            var jsonStart = text.IndexOf('{');
            var jsonEnd = text.LastIndexOf('}');
            if (jsonStart < 0 || jsonEnd < 0)
                return new AnalysisResult(false, false, "Invalid response format", ThreatLevel.Clean);

            var json = text[jsonStart..(jsonEnd + 1)];
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            var isSuspicious = root.GetProperty("isSuspicious").GetBoolean();
            var reasoning = root.GetProperty("reasoning").GetString() ?? "";
            var levelStr = root.GetProperty("level").GetString() ?? "Clean";
            var level = levelStr switch
            {
                "Suspicious" => ThreatLevel.Suspicious,
                "Malicious" => ThreatLevel.Malicious,
                _ => ThreatLevel.Clean
            };

            return new AnalysisResult(true, isSuspicious, reasoning, level);
        }
        catch
        {
            return new AnalysisResult(false, false, "Analysis failed", ThreatLevel.Clean);
        }
    }
}
