using static PlatformTools;

static class OverlapConfig
{
    public static SupportedPlatforms Platform => SupportedPlatforms.GBA;
    public static bool WriteToCsv => true;

    public static string CsvPath = "Findings.csv";

    public static bool ShouldSkipToken(string token)
    {
        if (string.IsNullOrWhiteSpace(token)) return false;
        token = token.Trim();
        return token.StartsWith("readptr(", StringComparison.OrdinalIgnoreCase);
    }
}
