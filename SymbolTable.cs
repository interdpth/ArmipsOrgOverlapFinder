//using System.Text.RegularExpressions;

//public class SymbolTable
//{
//    Dictionary<string, long> map = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
//    Dictionary<string, string> pendingExpr = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

//    static Regex equRegex = new Regex(@"^\s*([A-Za-z_\.@][A-Za-z0-9_\.@]*)\s+equ\s+(.+)$", RegexOptions.IgnoreCase);
//    public void AddResolved(string name, long value)
//    {
//        map[name] = value;
//        pendingExpr.Remove(name);
//    }
//    public void AddOrQueue(string line)
//    {
//        var m = equRegex.Match(line);
//        if (!m.Success) return;
//        string name = m.Groups[1].Value.Trim();
//        string expr = m.Groups[2].Value.Trim();
//        // Keep expression form for later evaluation
//        pendingExpr[name] = expr;
//    }

//    // Try to resolve as many pending expressions as possible
//    public void ResolveAll()
//    {
//        bool progressed;
//        int safety = 0;
//        do
//        {
//            progressed = false;
//            var keys = pendingExpr.Keys.ToArray();
//            foreach (var k in keys)
//            {
//                string expr = pendingExpr[k];
//                if (TryEvalExpression(expr, out long val))
//                {
//                    map[k] = val;
//                    pendingExpr.Remove(k);
//                    progressed = true;
//                }
//            }
//            safety++;
//            if (safety > 10000) break; // safety
//        } while (progressed);
//    }

//    public bool TryGet(string symbol, out long val)
//    {
//        if (map.TryGetValue(symbol, out val)) return true;
//        // allow numbers directly
//        if (TryParseNumber(symbol, out val)) return true;
//        return false;
//    }

//    // Attempt to evaluate expressions with + and - and parentheses (simple)
//    public bool TryEvalExpression(string expr, out long result)
//    {
//        result = 0;
//        try
//        {
//            // Replace token symbols with numeric values if available.
//            // Use regex to find identifiers and replace when possible.
//            string replaced = Regex.Replace(expr, @"([A-Za-z_@\.][A-Za-z0-9_@\.]*)", m =>
//            {
//                string t = m.Value;
//                if (map.TryGetValue(t, out long v)) return v.ToString();
//                return t; // keep as-is if unknown
//            }, RegexOptions.IgnoreCase);

//            // Replace hex formats: trailing h -> 0x..., $NN -> 0x, keep 0x as is.
//            replaced = replaced.Replace("'", ""); // just in case
//            replaced = Regex.Replace(replaced, @"([0-9A-Fa-f]+)h\b", "0x$1");    // 1234h -> 0x1234
//            replaced = Regex.Replace(replaced, @"\$(0*[0-9A-Fa-f]+)", "0x$1");   // $ABCD -> 0xABCD

//            // Reject only if *symbol identifiers* remain (not hex literals)
//            if (Regex.IsMatch(replaced, @"\b[A-Za-z_@\.][A-Za-z0-9_@\.]*\b"))
//            {
//                // allow 0x... hex literals
//                if (!Regex.IsMatch(replaced, @"0x[0-9A-Fa-f]+"))
//                    return false;
//            }

//            // Evaluate simple arithmetic supporting + and - and parentheses
//            result = EvaluateSimpleExpression(replaced);
//            return true;
//        }
//        catch
//        {
//            return false;
//        }
//    }

//    static long EvaluateSimpleExpression(string expr)
//    {
//        // Very small recursive descent for +, -, parens; numbers in decimal or 0x hex
//        int i = 0;
//        long ParseExpr()
//        {
//            long v = ParseTerm();
//            while (true)
//            {
//                SkipSpaces();
//                if (i < expr.Length && expr[i] == '+') { i++; long t = ParseTerm(); v += t; }
//                else if (i < expr.Length && expr[i] == '-') { i++; long t = ParseTerm(); v -= t; }
//                else break;
//            }
//            return v;
//        }
//        long ParseTerm()
//        {
//            SkipSpaces();
//            if (i < expr.Length && expr[i] == '(') { i++; long v = ParseExpr(); SkipSpaces(); if (i < expr.Length && expr[i] == ')') i++; return v; }
//            return ParseNumber();
//        }
//        long ParseNumber()
//        {
//            SkipSpaces();
//            if (i >= expr.Length) return 0;
//            int start = i;
//            if (expr.Substring(i).StartsWith("0x", StringComparison.OrdinalIgnoreCase))
//            {
//                i += 2;
//                int s = i;
//                while (i < expr.Length && IsHex(expr[i])) i++;
//                string hex = expr.Substring(s, i - s);
//                return Convert.ToInt64(hex, 16);
//            }
//            else
//            {
//                bool neg = false;
//                if (expr[i] == '+') { i++; }
//                else if (expr[i] == '-') { neg = true; i++; }
//                long val = 0;
//                while (i < expr.Length && Char.IsDigit(expr[i]))
//                {
//                    val = val * 10 + (expr[i] - '0'); i++;
//                }
//                return neg ? -val : val;
//            }
//        }
//        void SkipSpaces() { while (i < expr.Length && Char.IsWhiteSpace(expr[i])) i++; }
//        bool IsHex(char c) => ("0123456789abcdefABCDEF".IndexOf(c) >= 0);

//        i = 0;
//        return ParseExpr();
//    }

//    // Parse standalone number tokens like 0801234h, $80AB, 0x80ab, decimal
//    public static bool TryParseNumber(string token, out long value)
//    {
//        value = 0;
//        if (string.IsNullOrWhiteSpace(token))
//            return false;

//        token = token.Trim();

//        // Strip inline comments (//, ;, #) and trailing non-hex characters
//        int commentIndex = token.IndexOf("//", StringComparison.Ordinal);
//        if (commentIndex >= 0)
//            token = token.Substring(0, commentIndex);
//        commentIndex = token.IndexOf(';');
//        if (commentIndex >= 0)
//            token = token.Substring(0, commentIndex);
//        commentIndex = token.IndexOf('#');
//        if (commentIndex >= 0)
//            token = token.Substring(0, commentIndex);

//        token = token.Trim();
//        // trailing h hex
//        var m = Regex.Match(token, @"^([0-9A-Fa-f]+)h$", RegexOptions.IgnoreCase);
//        if (m.Success) { value = Convert.ToInt64(m.Groups[1].Value, 16); return true; }
//        if (token.StartsWith("$"))
//        {
//            var s = token.Substring(1);
//            value = Convert.ToInt64(s, 16); return true;
//        }
//        if (token.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
//        {
//            value = Convert.ToInt64(token.Substring(2), 16); return true;
//        }
//        // pure hex-looking token (>=3 hex digits)
//        if (Regex.IsMatch(token, @"^[0-9A-Fa-f]{3,}$"))
//        {
//            value = Convert.ToInt64(token, 16); return true;
//        }
//        if (long.TryParse(token, out value)) return true;
//        return false;
//    }

//    public void DumpPending()
//    {
//        if (pendingExpr.Count > 0)
//        {
//            WriteHelpers.WriteWarn("Unresolved equ entries:");
//            foreach (var kv in pendingExpr) Console.WriteLine($"  {kv.Key} = {kv.Value}");
//            WriteHelpers.WriteWarn("Unresolved equ entries finished.");
//        }
//    }
//}
