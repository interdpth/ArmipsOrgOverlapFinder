using System;
using System.IO;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using System.Linq;
using System.Formats.Asn1;

/*
OrgOverlapFinder_advanced.cs

Usage:
  csc OrgOverlapFinder_advanced.cs
  OrgOverlapFinder_advanced.exe C:\path\to\folderA C:\path\to\folderB

Features:
 - Recursively scans folderA and folderB for .asm/.s/.inc
 - Follows .include directives (relative to the including file) to collect a full file graph
 - Builds symbol table from "NAME equ EXPR" (supports hex formats: 0x, $, trailing h; decimal)
 - Evaluates simple expressions using + and - with symbols
 - Parses .org directives and resolves numeric, symbol, or expression forms
 - For unresolved labels, tries to find label in files and estimates address using nearest numeric .org and byte-size heuristics
 - Reports overlaps within ORG_TOLERANCE (20 bytes default)
*/

public static class ExternalIPSReader
{
  public  static string RunFlips(string sourceRom, string builtRom, string tag)
    {
        string flipsExe = Path.Combine("tools", "flips.exe");
        string outPatch = Path.Combine(Path.GetTempPath(), $"auto_patch_{tag}.ips");

        if (!File.Exists(flipsExe))
        {
            Console.WriteLine($"Error: flips.exe not found at {flipsExe}");
            return "";
        }

        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName = flipsExe,
                Arguments = $"--create \"{sourceRom}\" \"{builtRom}\" \"{outPatch}\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            var p = System.Diagnostics.Process.Start(psi);
            p.WaitForExit();
            Console.WriteLine($"Generated IPS: {outPatch}");
            return outPatch;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to run flips ({tag}): {ex.Message}");
            return "";
        }
    }

    class IPSPatch
    {
        public uint Offset;
        public int Size;
        public string Type; // "NORMAL" or "RLE"
    }

    public static void LoadIPSFile(string path, SymbolTable symtab)
    {
        if (!File.Exists(path)) return;

        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read);
        using var br = new BinaryReader(fs);

        // Check header
        var header = br.ReadBytes(5);
        if (System.Text.Encoding.ASCII.GetString(header) != "PATCH")
        {
            Console.WriteLine($"Skipping invalid IPS file: {path}");
            return;
        }

        var patches = new List<IPSPatch>();

        while (true)
        {
            // Read 3-byte offset or EOF
            byte[] offsetBytes = br.ReadBytes(3);
            if (offsetBytes.Length < 3) break;
            if (offsetBytes[0] == (byte)'E' && offsetBytes[1] == (byte)'O' && offsetBytes[2] == (byte)'F')
                break;

            uint offset = (uint)((offsetBytes[0] << 16) | (offsetBytes[1] << 8) | offsetBytes[2]);

            // Read 2-byte size
            byte[] sizeBytes = br.ReadBytes(2);
            if (sizeBytes.Length < 2) break;
            int size = (sizeBytes[0] << 8) | sizeBytes[1];

            if (size == 0)
            {
                // RLE record
                byte[] rleSizeBytes = br.ReadBytes(2);
                if (rleSizeBytes.Length < 2) break;
                int rleSize = (rleSizeBytes[0] << 8) | rleSizeBytes[1];
                br.ReadByte(); // RLE value (ignore)

                patches.Add(new IPSPatch
                {
                    Offset = offset,
                    Size = rleSize,
                    Type = "RLE"
                });
            }
            else
            {
                // Normal patch
                br.ReadBytes(size); // skip actual data
                patches.Add(new IPSPatch
                {
                    Offset = offset,
                    Size = size,
                    Type = "NORMAL"
                });
            }
        }

        // Add each patch as a "symbol" in the symbol table
        foreach (var p in patches)
        {
            uint realOffset = PlatformTools.GetOffset(p.Offset, OverlapConfig.Platform);
            string name = $"IPS_{Path.GetFileNameWithoutExtension(path)}_{realOffset:X8}";
            long addr = realOffset;
            symtab.AddResolved(name, addr);
            // Optional: store size as part of hint
            Console.WriteLine($"Added IPS patch: {name} @ 0x{addr:X6} size={p.Size} ({p.Type})");
        }
    }
}

static class ExternalSymbolReaders
{
    static Regex symLine1 =
        new Regex(@"^\s*([0-9A-Fa-f]+)\s+([A-Za-z_@\.][A-Za-z0-9_@\.]*)");

    static Regex symLine2 =
        new Regex(@"^\s*([A-Za-z_@\.][A-Za-z0-9_@\.]*)\s*=\s*([0-9A-Fa-f]+)");

    public static void LoadSymFile(string path, SymbolTable symtab)
    {
        var ls = File.ReadAllLines(path);
        for (int i = 0; i < ls.Count(); i++)
        {
            string line = ls[i];
            Match m;
            if ((m = symLine1.Match(line)).Success ||
                (m = symLine2.Match(line)).Success)
            {
                string name = m.Groups[2].Value;
                string val = m.Groups[1].Value;
                if (SymbolTable.TryParseNumber(val, out long addr))
                    symtab.AddResolved(name, addr);
            }
        }
    }

    public static void LoadMapFile(string path, SymbolTable symtab)
    {
        foreach (var line in File.ReadAllLines(path))
        {
            var parts = line.Split(new[] { ' ', '\t' },
                                   StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2) continue;

            if (SymbolTable.TryParseNumber(parts[0], out long addr))
                symtab.AddResolved(parts[1], addr);
            else if (SymbolTable.TryParseNumber(parts[1], out addr))
                symtab.AddResolved(parts[0], addr);
        }
    }
}

public static class RegexTypes
{
    public static Regex includeRegex = new Regex(@"^\s*\.include\s+[""']?([^""'\s]+)[""']?", RegexOptions.IgnoreCase);
    public static Regex orgRegex = new Regex(@"\.org\s+([^\s;#]+)?", RegexOptions.IgnoreCase);
    public static Regex labelRegex = new Regex(@"^\s*([A-Za-z_\.\@\@][A-Za-z0-9_\.\@\@]*):\s*$");
    public static Regex incbinRegex = new Regex(@"\.incbin\s+""[^""]+""(?:\s*,\s*(\$?[0-9A-Fa-fx]+))?(?:\s*,\s*(\$?[0-9A-Fa-fx]+))?", RegexOptions.IgnoreCase);
    public static Regex dataByteRegex = new Regex(@"^\s*(?:\.byte|\.db)\b", RegexOptions.IgnoreCase);
    public static Regex dataHalfRegex = new Regex(@"^\s*(?:\.hword|\.half)\b", RegexOptions.IgnoreCase);
    public static Regex dataWordRegex = new Regex(@"^\s*(?:\.word|\.4byte)\b", RegexOptions.IgnoreCase);
    public static Regex dataAsciiRegex = new Regex(@"^\s*(?:\.ascii|\.asciz|\.string)\b", RegexOptions.IgnoreCase);
    public static Regex definelabelRegex = new Regex(@"^\s*\.definelabel\s+([A-Za-z_\.@][A-Za-z0-9_\.@]*)\s*,\s*([A-Za-z0-9_\.@+\-]+)",
              RegexOptions.IgnoreCase);
}

public class SymbolTable
{
    Dictionary<string, long> map = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
    Dictionary<string, string> pendingExpr = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    static Regex equRegex = new Regex(@"^\s*([A-Za-z_\.@][A-Za-z0-9_\.@]*)\s+equ\s+(.+)$", RegexOptions.IgnoreCase);
    public void AddResolved(string name, long value)
    {
        map[name] = value;
        pendingExpr.Remove(name);
    }
    public void AddOrQueue(string line)
    {
        var m = equRegex.Match(line);
        if (!m.Success) return;
        string name = m.Groups[1].Value.Trim();
        string expr = m.Groups[2].Value.Trim();
        // Keep expression form for later evaluation
        pendingExpr[name] = expr;
    }

    // Try to resolve as many pending expressions as possible
    public void ResolveAll()
    {
        bool progressed;
        int safety = 0;
        do
        {
            progressed = false;
            var keys = pendingExpr.Keys.ToArray();
            foreach (var k in keys)
            {
                string expr = pendingExpr[k];
                if (TryEvalExpression(expr, out long val))
                {
                    map[k] = val;
                    pendingExpr.Remove(k);
                    progressed = true;
                }
            }
            safety++;
            if (safety > 10000) break; // safety
        } while (progressed);
    }

    public bool TryGet(string symbol, out long val)
    {
        if (map.TryGetValue(symbol, out val)) return true;
        // allow numbers directly
        if (TryParseNumber(symbol, out val)) return true;
        return false;
    }

    // Attempt to evaluate expressions with + and - and parentheses (simple)
    public bool TryEvalExpression(string expr, out long result)
    {
        result = 0;
        try
        {
            // Replace token symbols with numeric values if available.
            // Use regex to find identifiers and replace when possible.
            string replaced = Regex.Replace(expr, @"([A-Za-z_@\.][A-Za-z0-9_@\.]*)", m =>
            {
                string t = m.Value;
                if (map.TryGetValue(t, out long v)) return v.ToString();
                return t; // keep as-is if unknown
            }, RegexOptions.IgnoreCase);

            // Replace hex formats: trailing h -> 0x..., $NN -> 0x, keep 0x as is.
            replaced = replaced.Replace("'", ""); // just in case
            replaced = Regex.Replace(replaced, @"([0-9A-Fa-f]+)h\b", "0x$1");    // 1234h -> 0x1234
            replaced = Regex.Replace(replaced, @"\$(0*[0-9A-Fa-f]+)", "0x$1");   // $ABCD -> 0xABCD

            // Reject only if *symbol identifiers* remain (not hex literals)
            if (Regex.IsMatch(replaced, @"\b[A-Za-z_@\.][A-Za-z0-9_@\.]*\b"))
            {
                // allow 0x... hex literals
                if (!Regex.IsMatch(replaced, @"0x[0-9A-Fa-f]+"))
                    return false;
            }

            // Evaluate simple arithmetic supporting + and - and parentheses
            result = EvaluateSimpleExpression(replaced);
            return true;
        }
        catch
        {
            return false;
        }
    }

    static long EvaluateSimpleExpression(string expr)
    {
        // Very small recursive descent for +, -, parens; numbers in decimal or 0x hex
        int i = 0;
        long ParseExpr()
        {
            long v = ParseTerm();
            while (true)
            {
                SkipSpaces();
                if (i < expr.Length && expr[i] == '+') { i++; long t = ParseTerm(); v += t; }
                else if (i < expr.Length && expr[i] == '-') { i++; long t = ParseTerm(); v -= t; }
                else break;
            }
            return v;
        }
        long ParseTerm()
        {
            SkipSpaces();
            if (i < expr.Length && expr[i] == '(') { i++; long v = ParseExpr(); SkipSpaces(); if (i < expr.Length && expr[i] == ')') i++; return v; }
            return ParseNumber();
        }
        long ParseNumber()
        {
            SkipSpaces();
            if (i >= expr.Length) return 0;
            int start = i;
            if (expr.Substring(i).StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                i += 2;
                int s = i;
                while (i < expr.Length && IsHex(expr[i])) i++;
                string hex = expr.Substring(s, i - s);
                return Convert.ToInt64(hex, 16);
            }
            else
            {
                bool neg = false;
                if (expr[i] == '+') { i++; }
                else if (expr[i] == '-') { neg = true; i++; }
                long val = 0;
                while (i < expr.Length && Char.IsDigit(expr[i]))
                {
                    val = val * 10 + (expr[i] - '0'); i++;
                }
                return neg ? -val : val;
            }
        }
        void SkipSpaces() { while (i < expr.Length && Char.IsWhiteSpace(expr[i])) i++; }
        bool IsHex(char c) => ("0123456789abcdefABCDEF".IndexOf(c) >= 0);

        i = 0;
        return ParseExpr();
    }

    // Parse standalone number tokens like 0801234h, $80AB, 0x80ab, decimal
    public static bool TryParseNumber(string token, out long value)
    {
        value = 0;
        if (string.IsNullOrWhiteSpace(token))
            return false;

        token = token.Trim();

        // Strip inline comments (//, ;, #) and trailing non-hex characters
        int commentIndex = token.IndexOf("//", StringComparison.Ordinal);
        if (commentIndex >= 0)
            token = token.Substring(0, commentIndex);
        commentIndex = token.IndexOf(';');
        if (commentIndex >= 0)
            token = token.Substring(0, commentIndex);
        commentIndex = token.IndexOf('#');
        if (commentIndex >= 0)
            token = token.Substring(0, commentIndex);

        token = token.Trim();
        // trailing h hex
        var m = Regex.Match(token, @"^([0-9A-Fa-f]+)h$", RegexOptions.IgnoreCase);
        if (m.Success) { value = Convert.ToInt64(m.Groups[1].Value, 16); return true; }
        if (token.StartsWith("$"))
        {
            var s = token.Substring(1);
            value = Convert.ToInt64(s, 16); return true;
        }
        if (token.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            value = Convert.ToInt64(token.Substring(2), 16); return true;
        }
        // pure hex-looking token (>=3 hex digits)
        if (Regex.IsMatch(token, @"^[0-9A-Fa-f]{3,}$"))
        {
            value = Convert.ToInt64(token, 16); return true;
        }
        if (long.TryParse(token, out value)) return true;
        return false;
    }

    public void DumpPending()
    {
        if (pendingExpr.Count > 0)
        {
            WriteHelpers.WriteWarn("Unresolved equ entries:");
            foreach (var kv in pendingExpr) Console.WriteLine($"  {kv.Key} = {kv.Value}");
            WriteHelpers.WriteWarn("Unresolved equ entries finished.");
        }
    }
}

class OrgEntry
{
    public string? FilePath;
    public int Line;
    public bool HasValue;
    public uint Address;
    public string RawToken = "";
    public string Hint = "";
    public uint size;
}

class Program
{
    const int ORG_TOLERANCE = 20;
    const int AVG_BYTES_PER_LINE = 4;
    static SymbolTable symtab = new SymbolTable();
    static List<string> allFiles = new List<string>();
    static HashSet<string> visitedFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    static List<string> CollectExtraFiles(string[] args, string flag)
    {
        var list = new List<string>();
        for (int i = 0; i < args.Length; i++)
        {
            if (args[i].Equals(flag, StringComparison.OrdinalIgnoreCase))
            {
                for (int j = i + 1; j < args.Length && !args[j].StartsWith("--"); j++)
                    list.Add(args[j]);
            }
        }
        return list;
    }


    static void Main(string[] args)
    {
        string? patchA=null;
        string? patchB = null;
        if (args.Length < 2)
        {
            Console.WriteLine("Usage: OrgOverlapFinder <folderA> <folderB> [--extraA files...] [--extraB files...] [--source-rom][--builtA-rom][--builtB-rom]");
            return;
        }
        string? sourceRomPath = null;
        string? builtRomAPath = null;
        string? builtRomBPath = null;
        string folderA = args[0];
        string folderB = args[1];
        var extraA = CollectExtraFiles(args, "--extraA");
        var extraB = CollectExtraFiles(args, "--extraB");
        // Build file graph by scanning both folders and following includes.
        CollectFilesWithIncludes(folderA);
        CollectFilesWithIncludes(folderB);
        for (int i = 0; i < args.Length; i++)
        {
            if (args[i].Equals("--source-rom", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
                sourceRomPath = args[++i];
            if (args[i].Equals("--builtA-rom", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
                builtRomAPath = args[++i];
            if (args[i].Equals("--builtB-rom", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
                builtRomBPath = args[++i];
        }

        if(sourceRomPath != null && builtRomAPath != null)
        {
            patchA= ExternalIPSReader.RunFlips(sourceRomPath, builtRomAPath, "A");
            extraA.Add(patchA);
        }
        if (sourceRomPath != null && builtRomBPath != null)
        {
            patchB=ExternalIPSReader.RunFlips(sourceRomPath, builtRomBPath, "B");
            extraB.Add(patchB);
        }

        Console.WriteLine($"Collected {allFiles.Count} files (including resolved .includes).");
        foreach (var f in extraA.Concat(extraB))
        {
            if (!File.Exists(f)) continue;

            if (f.EndsWith(".sym", StringComparison.OrdinalIgnoreCase))
                ExternalSymbolReaders.LoadSymFile(f, symtab);
            else if (f.EndsWith(".ips", StringComparison.OrdinalIgnoreCase))
                ExternalIPSReader.LoadIPSFile(f, symtab);
            else if (f.EndsWith(".map", StringComparison.OrdinalIgnoreCase))
                ExternalSymbolReaders.LoadMapFile(f, symtab);
            else if (f.EndsWith(".inc", StringComparison.OrdinalIgnoreCase))
                foreach (var line in File.ReadAllLines(f))
                    symtab.AddOrQueue(line);
        }

        symtab.ResolveAll();
        symtab.DumpPending();

        // Second pass: collect .org entries
        var entriesA = new List<OrgEntry>();
        var entriesB = new List<OrgEntry>();

        // We'll decide membership by file path starting with folderA or folderB (normalize)
        string normA = Path.GetFullPath(folderA).TrimEnd('\\', '/');
        string normB = Path.GetFullPath(folderB).TrimEnd('\\', '/');

        foreach (var f in allFiles)
        {
            var res = CollectOrgsFromFile(f);
            if (Path.GetFullPath(f).StartsWith(normA, StringComparison.OrdinalIgnoreCase))
                entriesA.AddRange(res);
            else if (Path.GetFullPath(f).StartsWith(normB, StringComparison.OrdinalIgnoreCase))
                entriesB.AddRange(res);
            else
            {
                // If file is from include outside both roots, add to both lists for symbol resolution / label lookup
                entriesA.AddRange(res);
                entriesB.AddRange(res);
            }
        }

        // Try resolve unknown tokens using symbol table or label scanning and heuristics
        ResolveUnknownOrgs(entriesA);
        ResolveUnknownOrgs(entriesB);

        // Print unresolved
        PrintUnresolved(entriesA, "FolderA");
        PrintUnresolved(entriesB, "FolderB");

        // Find overlaps
        FindOverlaps(entriesA, entriesB);

        if(patchA != null)
        {
            File.Delete(patchA);

        }
        if (patchB != null)
        {
            File.Delete(patchB);

        }
        Console.WriteLine("Done.");
    }

    static void CollectFilesWithIncludes(string startFolder)
    {
        // Gather initial files
        var files = Directory.GetFiles(startFolder, "*.*", SearchOption.AllDirectories)
                    .Where(fn => fn.EndsWith(".asm", StringComparison.OrdinalIgnoreCase)
                              || fn.EndsWith(".s", StringComparison.OrdinalIgnoreCase)
                              || fn.EndsWith(".inc", StringComparison.OrdinalIgnoreCase))
                    .ToList();

        // We'll process a queue to follow includes
        var queue = new Queue<string>(files);
        foreach (var f in files)
        {
            var full = Path.GetFullPath(f);
            if (!visitedFiles.Contains(full)) { visitedFiles.Add(full); allFiles.Add(full); }
        }

        while (queue.Count > 0)
        {
            string? f = queue.Dequeue();
            string baseDir = Path.GetDirectoryName(f);
            string[] lines;
            try { lines = File.ReadAllLines(f); } catch { continue; }
            foreach (var line in lines)
            {
                var m = RegexTypes.includeRegex.Match(line);
                if (m.Success)
                {
                    string includePath = m.Groups[1].Value.Trim().Replace('/', Path.DirectorySeparatorChar).Replace('\\', Path.DirectorySeparatorChar);
                    // Resolve relative to baseDir
                    string candidate = Path.Combine(baseDir, includePath);
                    if (!File.Exists(candidate))
                    {
                        // Try with quotes removal or direct filename
                        candidate = Path.Combine(baseDir, includePath.Trim('"').Trim('\''));
                    }
                    if (File.Exists(candidate))
                    {
                        string full = Path.GetFullPath(candidate);
                        if (!visitedFiles.Contains(full))
                        {
                            visitedFiles.Add(full); allFiles.Add(full); queue.Enqueue(full);
                        }
                    }
                    else
                    {
                        // try a few fallback attempts: maybe include uses forward slashes or missing extension
                        try
                        {
                            var alt = Path.GetFullPath(Path.Combine(baseDir, includePath));
                            if (File.Exists(alt))
                            {
                                if (!visitedFiles.Contains(alt)) { visitedFiles.Add(alt); allFiles.Add(alt); queue.Enqueue(alt); }
                            }
                        }
                        catch { }
                    }
                }
            }
        }
    }

    static List<OrgEntry> CollectOrgsFromFile(string path)
    {
        var results = new List<OrgEntry>();
        string[] lines;
        try { lines = File.ReadAllLines(path); } catch { return results; }
        for (int i = 0; i < lines.Length; i++)
        {
            var m = RegexTypes.orgRegex.Match(lines[i]);
            if (m.Success)
            {
                string token = m.Groups[1].Success ? m.Groups[1].Value.Trim() : "";
                var e = new OrgEntry() { FilePath = path, Line = i + 1 };
                if (!string.IsNullOrEmpty(token))
                {
                    // try numeric or expression
                    if (SymbolTable.TryParseNumber(token, out long num))
                    {
                        e.HasValue = true; e.Address = (uint)num; e.Hint = $"parsed numeric '{token}'";
                    }
                    else if (symtab.TryEvalExpression(token, out num))
                    {
                        e.HasValue = true; e.Address = (uint)num; e.Hint = $"evaluated expr '{token}'";
                    }
                    else
                    {
                        e.RawToken = token; e.Hint = "unresolved token";
                    }
                }
                else
                {
                    e.RawToken = ""; e.Hint = "no token";
                }
                results.Add(e);
            }
        }
        return results;
    }

    static void ResolveUnknownOrgs(List<OrgEntry> entries)
    {
        // Group by file for quick access
        var byFile = entries.GroupBy(x => x.FilePath).ToDictionary(g => g.Key, g => g.OrderBy(x => x.Line).ToList());

        // Build a map of labels (file->label->line)
        var labelMap = new Dictionary<string, Dictionary<string, int>>(StringComparer.OrdinalIgnoreCase);
        foreach (var file in byFile.Keys)
        {
            string[] lines;
            try { lines = File.ReadAllLines(file); } catch { continue; }
            var map = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < lines.Length; i++)
            {
                var lm = RegexTypes.labelRegex.Match(lines[i]);
                if (lm.Success)
                {
                    string name = lm.Groups[1].Value;
                    map[name] = i + 1;
                }
                if (!lm.Success)
                {
                    lm = RegexTypes.definelabelRegex.Match(lines[i]);
                    if (lm.Success)
                    {
                        string name = lm.Groups[1].Value;
                        map[name] = i + 1;
                    }
                }
            }
            labelMap[file] = map;
        }

        // For each unresolved entry, try to resolve from symbol table or label scanning + heuristic estimation
        foreach (var e in entries)
        {
            if (e.HasValue) continue;
            if (!string.IsNullOrEmpty(e.RawToken))
            {
                // try symbol table lookups (maybe token is expression like FreeIWRam + 4)
                if (symtab.TryEvalExpression(e.RawToken, out long v))
                {
                    e.HasValue = true; e.Address = (uint)v; e.Hint = $"evaluated token '{e.RawToken}' via symbol table";
                    continue;
                }
                // try if token is a label in same file
                if (labelMap.TryGetValue(e.FilePath, out var m) && m.TryGetValue(e.RawToken, out int labelLine))
                {
                    // find previous numeric .org in this file
                    var fileOrgs = byFile[e.FilePath];
                    OrgEntry prev = null;
                    foreach (var oe in fileOrgs)
                    {
                        if (oe.Line < labelLine && oe.HasValue) prev = oe;
                    }
                    if (prev != null)
                    {
                        // estimate bytes between prev.Line and labelLine
                        uint est = EstimateBytesBetween(prev.FilePath, prev.Line - 1, labelLine - 1, prev.Address);
                        e.HasValue = true; e.Address = est; e.Hint = $"estimated label '{e.RawToken}' from .org at line {prev.Line}";
                        continue;
                    }
                }
                // try to find token as label in any file
                bool found = false;
                foreach (var kv in labelMap)
                {
                    if (kv.Value.TryGetValue(e.RawToken, out int lblLine))
                    {
                        // see if there is a numeric .org earlier in that file
                        var fileOrgs = byFile.ContainsKey(kv.Key) ? byFile[kv.Key] : new List<OrgEntry>();
                        OrgEntry prev = null;
                        foreach (var oe in fileOrgs) if (oe.Line < lblLine && oe.HasValue) prev = oe;
                        if (prev != null)
                        {
                            uint est = EstimateBytesBetween(prev.FilePath, prev.Line - 1, lblLine - 1, prev.Address);
                            e.HasValue = true; e.Address = est; e.Hint = $"resolved label '{e.RawToken}' by scanning {kv.Key}";
                            found = true; break;
                        }
                    }
                }
                if (found) continue;

                // last resort: if token looks like a filename, try to find file and use its numeric .org
                try
                {
                    var filenameOnly = Path.GetFileName(e.RawToken.Trim('"').Trim('\''));
                    foreach (var file in byFile.Keys)
                    {
                        if (Path.GetFileName(file).Equals(filenameOnly, StringComparison.OrdinalIgnoreCase))
                        {
                            // find numeric orgs in that file
                            var fos = byFile[file].Where(x => x.HasValue).OrderBy(x => x.Line).ToList();
                            if (fos.Count > 0)
                            {
                                // use first numeric org
                                e.HasValue = true; e.Address = fos[0].Address; e.Hint = $"resolved by referenced file {file}";
                                break;
                            }
                        }
                    }
                }
                catch { }

                // otherwise leave unresolved
                if (!e.HasValue) e.Hint = "UNRESOLVED (no symbol, no label, heuristics failed)";
            }
            else
            {
                e.Hint = "UNRESOLVED (no token)";
            }
        }
    }

    static uint EstimateBytesBetween(string file, int prevIndex, int targetIndex, uint prevAddr)
    {
        string[] lines = File.ReadAllLines(file);
        uint addr = prevAddr;
        for (int i = prevIndex + 1; i <= targetIndex && i < lines.Length; i++)
        {
            string l = lines[i].Trim();
            if (string.IsNullOrEmpty(l) || l.StartsWith(";") || l.StartsWith("#")) continue;
            var mInc = RegexTypes.incbinRegex.Match(l);
            if (mInc.Success)
            {
                // try capture an explicit length (third arg)
                if (mInc.Groups.Count >= 3 && mInc.Groups[2].Success)
                {
                    string token = mInc.Groups[2].Value.Trim().Trim(',');
                    if (SymbolTable.TryParseNumber(token, out long len)) { addr += (uint)len; continue; }
                }
                if (mInc.Groups.Count >= 4 && mInc.Groups[3].Success)
                {
                    string token = mInc.Groups[3].Value.Trim().Trim(',');
                    if (SymbolTable.TryParseNumber(token, out long len)) { addr += (uint)len; continue; }
                }
                addr += AVG_BYTES_PER_LINE;
                continue;
            }
            if (RegexTypes.dataByteRegex.IsMatch(l))
            {
                int c = l.Count(ch => ch == ',') + 1;
                addr += (uint)c; continue;
            }
            if (RegexTypes.dataHalfRegex.IsMatch(l)) { int c = l.Count(ch => ch == ',') + 1; addr += (uint)(c * 2); continue; }
            if (RegexTypes.dataWordRegex.IsMatch(l)) { int c = l.Count(ch => ch == ',') + 1; addr += (uint)(c * 4); continue; }
            if (RegexTypes.dataAsciiRegex.IsMatch(l))
            {
                var m = Regex.Match(l, "\"([^\"]*)\"");
                if (m.Success) addr += (uint)m.Groups[1].Value.Length;
                else addr += AVG_BYTES_PER_LINE;
                continue;
            }
            // anything else we count as avg
            addr += AVG_BYTES_PER_LINE;
        }
        return addr;
    }

    static void PrintUnresolved(List<OrgEntry> list, string label)
    {
        bool any = false;
        foreach (var e in list) if (!e.HasValue) { any = true; break; }
        if (!any) return;
        WriteHelpers.WriteWarn($"--- UNRESOLVED .org entries ({label}) ---");
        foreach (var e in list.Where(x => !x.HasValue))
        {
            Console.WriteLine($"{e.FilePath}:{e.Line} token='{e.RawToken}' hint='{e.Hint}'");
        }
    }

    static void FindOverlaps(List<OrgEntry> A, List<OrgEntry> B)
    {
        //if (OverlapConfig.WriteToCsv)
        //{
        //    File.Delete("Findings.csv");
        //}
        Console.WriteLine("--- Checking overlaps ---");
        int found = 0;
        foreach (var a in A.Where(x => x.HasValue))
        {
            foreach (var b in B.Where(x => x.HasValue))
            {
                int diff = (int)Math.Abs((long)a.Address - (long)b.Address);
                if (diff <= ORG_TOLERANCE)
                {
                    found++;
                    Console.WriteLine($"Overlap (±{ORG_TOLERANCE}):");
                    WriteHelpers.WriteA($"  A: {a.FilePath}:{a.Line} -> 0x{a.Address:X8} ({a.Hint})");
                    WriteHelpers.WriteB($"  B: {b.FilePath}:{b.Line} -> 0x{b.Address:X8} ({b.Hint})");
                    Console.WriteLine();
                }
            }
        }
        if (found == 0) Console.WriteLine("No overlaps found within tolerance.");
    }
}
