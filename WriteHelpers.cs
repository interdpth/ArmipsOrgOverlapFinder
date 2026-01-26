static class WriteHelpers
{
    public static void WriteA(string text)
    {
        var old = Console.ForegroundColor;
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine(text);
        Console.ForegroundColor = old;
    }

    public static void WriteB(string text)
    {
        var old = Console.ForegroundColor;
        Console.ForegroundColor = ConsoleColor.Blue;
        Console.WriteLine(text);
        Console.ForegroundColor = old;
    }

    public static void WriteWarn(string text)
    {
        var old = Console.ForegroundColor;
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine(text);
        Console.ForegroundColor = old;
    }
}
