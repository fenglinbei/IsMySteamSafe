using System.Text.Json;
using System.Text.Json.Nodes;
using IsMySteamSafe.Core.Utilities;

namespace IsMySteamSafe.Core.Reporting;

public static class JsonRedaction
{
    private static readonly HashSet<string> Secrets = new(StringComparer.OrdinalIgnoreCase)
        { "password", "passwd", "token", "shared_secret", "identity_secret", "authorization", "cookie", "sessionid" };
    public static string Redact(string text)
    {
        JsonNode? root = JsonNode.Parse(text);
        Visit(root);
        return root?.ToJsonString(new JsonSerializerOptions { WriteIndented = true }) ?? "null";
    }
    private static void Visit(JsonNode? node)
    {
        if (node is JsonObject obj)
            foreach (string key in obj.Select(pair => pair.Key).ToArray())
            {
                if (Secrets.Contains(key)) obj[key] = "[REDACTED]";
                else if (obj[key] is JsonValue value && value.TryGetValue(out string? text)) obj[key] = FileUtilities.RedactSensitiveText(text);
                else Visit(obj[key]);
            }
        else if (node is JsonArray array)
            for (int index = 0; index < array.Count; index++)
                if (array[index] is JsonValue value && value.TryGetValue(out string? text)) array[index] = FileUtilities.RedactSensitiveText(text);
                else Visit(array[index]);
    }
}
