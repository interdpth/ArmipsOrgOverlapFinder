public static class PlatformTools
{
    public enum SupportedPlatforms
    {
        GBA,
        PC
    }

    public static uint GetOffset(uint offset, SupportedPlatforms cfg)
    {
        if (cfg == SupportedPlatforms.GBA)
        {
            return offset + 0x8000000;
        }
        if (cfg == SupportedPlatforms.PC) return offset;
        throw new NotImplementedException("Platform not supported");
    }
}
