//using System.Text.RegularExpressions;

//public static class RegexTypes
//{
//    public static Regex includeRegex = new Regex(@"^\s*\.include\s+[""']?([^""'\s]+)[""']?", RegexOptions.IgnoreCase);
//    public static Regex orgRegex = new Regex(@"\.org\s+([^\s;#]+)?", RegexOptions.IgnoreCase);
//    public static Regex labelRegex = new Regex(@"^\s*([A-Za-z_\.\@\@][A-Za-z0-9_\.\@\@]*):\s*$");
//    public static Regex incbinRegex = new Regex(@"\.incbin\s+""[^""]+""(?:\s*,\s*(\$?[0-9A-Fa-fx]+))?(?:\s*,\s*(\$?[0-9A-Fa-fx]+))?", RegexOptions.IgnoreCase);
//    public static Regex dataByteRegex = new Regex(@"^\s*(?:\.byte|\.db)\b", RegexOptions.IgnoreCase);
//    public static Regex dataHalfRegex = new Regex(@"^\s*(?:\.hword|\.half)\b", RegexOptions.IgnoreCase);
//    public static Regex dataWordRegex = new Regex(@"^\s*(?:\.word|\.4byte)\b", RegexOptions.IgnoreCase);
//    public static Regex dataAsciiRegex = new Regex(@"^\s*(?:\.ascii|\.asciz|\.string)\b", RegexOptions.IgnoreCase);
//    public static Regex definelabelRegex =  new Regex(@"^\s*\.definelabel\s+([A-Za-z_\.@][A-Za-z0-9_\.@]*)\s*,\s*([A-Za-z0-9_\.@+\-]+)",
//              RegexOptions.IgnoreCase);
//}
