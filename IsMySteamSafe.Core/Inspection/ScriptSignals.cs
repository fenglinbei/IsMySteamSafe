using System.Text;
using System.Text.RegularExpressions;

namespace IsMySteamSafe.Core.Inspection;

/// <summary>Bounded literal normalization. Never evaluates scripts or invokes a command interpreter.</summary>
public static class ScriptSignals
{
    private const int Limit = 2 * 1024 * 1024;
    private static readonly Regex JoinLiterals = new("""(?<q>['"])(?<left>[A-Za-z0-9_./:\\-]{0,512})\k<q>\s*\+\s*\k<q>(?<right>[A-Za-z0-9_./:\\-]{0,512})\k<q>""",
        RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    private static readonly Regex Encoded = new("""(?:FromBase64String\s*\(\s*['"]|-(?:enc|encodedcommand)\s+)(?<data>[A-Za-z0-9+/]{32,65536}={0,2})""",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    private static readonly Regex Secret = new("""(?i)(?<key>(?:password|passwd|token|shared_secret|identity_secret|authorization|cookie|sessionid)["']?\s*[:=]\s*["']?)[^"'\s&;,}\\]+""",
        RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    private static readonly Regex QuotedSecret = new("""(?i)(?<key>(?:password|passwd|token|shared_secret|identity_secret|authorization|cookie|sessionid)["']?\s*[:=]\s*)(?<q>["'])(?:(?!\k<q>).){0,8192}\k<q>""",
        RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    private static readonly Regex Query = new("""(?i)(?<key>[?&][^=\s"'<>]{1,64}=)[^&\s"'<>]*""",
        RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));

    public static string Normalize(string text)
    {
        string result = text.Length > Limit ? text[..Limit] : text;
        try
        {
            for (int i = 0; i < 6; i++)
            {
                string next = JoinLiterals.Replace(result, "${q}${left}${right}${q}");
                if (next == result) break;
                result = next;
            }
            StringBuilder decoded = new(result);
            foreach (Match match in Encoded.Matches(result).Cast<Match>().Take(4))
            {
                try
                {
                    byte[] bytes = Convert.FromBase64String(match.Groups["data"].Value);
                    try
                    {
                        string candidate = bytes.Length > 1 && bytes[1] == 0 ? Encoding.Unicode.GetString(bytes) : Encoding.UTF8.GetString(bytes);
                        decoded.Append('\n').Append(candidate);
                    }
                    finally { Array.Clear(bytes); }
                }
                catch (FormatException) { }
            }
            return decoded.ToString();
        }
        catch (RegexMatchTimeoutException) { return result; }
    }

    private static Regex SignalPattern(string expression) => new(expression,
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.NonBacktracking, TimeSpan.FromMilliseconds(75));
    private static readonly Regex NetworkRead = SignalPattern(@"\b(?:Download(?:String|Data|File)(?:Task)?(?:Async)?|Get(?:ByteArray|String|Stream)Async|fetch|urlopen|urlretrieve)\s*\(|\b(?:requests|httpx|urllib\.request|https?|http)\s*\.\s*(?:get|request|Fetch|Get|Download)\s*\(|\b(?:Invoke-WebRequest|Invoke-RestMethod)\b");
    private static readonly Regex DynamicExecution = SignalPattern(@"\b(?:Assembly\s*\.\s*Load(?:File|From)?|CompileAssemblyFromSource|CSharpScript\s*\.\s*RunAsync)\s*\(|(?:^|[^.\w])(?:loadstring|load|eval|exec|RunString|RunStringEx|CompileString)\s*\(|\b(?:Invoke-Expression|iex)\b");
    private static readonly Regex ProcessExecution = SignalPattern(@"\b(?:Process\s*\.\s*Start|subprocess\s*\.\s*(?:Popen|run|call)|os\s*\.\s*(?:system|execute)|child_process\s*\.\s*(?:exec|spawn)(?:Sync)?|shell\s*\.\s*Run|WScript\s*\.\s*Shell)\s*\(|\b(?:Start-Process|mshta|rundll32)\b");
    private static readonly Regex FileWrite = SignalPattern(@"\b(?:WriteAll(?:Bytes|Text)(?:Async)?|writeFile(?:Sync)?|write_bytes|write_text|writefile|write)\s*\(|\b(?:Set-Content|Out-File|Copy-Item)\b");
    private static readonly Regex FileRead = SignalPattern(@"\b(?:ReadAll(?:Bytes|Text|Lines)(?:Async)?|readFile(?:Sync)?|read_bytes|read_text|readfile|open|file\s*\.\s*Read)\s*\(|\b(?:Get-Content|Get-ChildItem)\b");
    private static readonly Regex NetworkUpload = SignalPattern(@"\b(?:Upload(?:Data|String|File)(?:Task)?(?:Async)?|Post(?:Async|AsJsonAsync)|SendAsync|send_file)\s*\(|\b(?:requests|httpx|axios|http)\s*\.\s*(?:post|Post)\s*\(|\b(?:Invoke-WebRequest|Invoke-RestMethod)\b[^\r\n]{0,256}-Method\s+Post\b");
    private static readonly Regex FileCopy = SignalPattern(@"\b(?:File\s*\.\s*Copy|copyFile(?:Sync)?|shutil\s*\.\s*copy(?:file|2)?|file\s*\.\s*Copy)\s*\(|\bCopy-Item\b");
    private static readonly Regex RecursiveDelete = SignalPattern(@"\b(?:shutil\s*\.\s*rmtree|fs\s*\.\s*(?:rm|rmSync|rmdirSync)|Directory\s*\.\s*Delete)\s*\(|\bRemove-Item\b[^\r\n]{0,256}-(?:Recurse|r)\b");
    private static readonly Regex PayloadName = SignalPattern(@"\.(?:exe|dll|ps1|bat|cmd|py|js|cs|csx|lua)(?:[^a-z0-9_]|$)");
    private static readonly Regex CredentialStore = SignalPattern(@"\b(?:Login Data|Local State|loginusers\.vdf|config\.vdf|shared_secret|identity_secret|Cookies|ssfn[0-9]+)\b|\.mafile\b");
    private static readonly Regex WorkshopTarget = SignalPattern(@"steamapps[/\\]+workshop[/\\]+content|(?:workshop|mod)[/\\]+(?:content|[0-9]{3,20})");

    public static IReadOnlyList<string> Analyze(string text, string extension = "")
    {
        // Strings participate only as data (paths or known family markers); API names must
        // occur outside comments and quoted strings. This is a bounded heuristic, not a parser.
        (string uncommented, _) = LexicalViews(text.Length > Limit ? text[..Limit] : text, extension);
        (string value, string code) = LexicalViews(Normalize(uncommented), extension);
        HashSet<string> signals = new(StringComparer.Ordinal);
        const int windowSize = 4096, stride = 2048;
        for (int offset = 0; offset < value.Length; offset += stride)
        {
            int length = Math.Min(windowSize, value.Length - offset);
            string nearby = value.Substring(offset, length), executable = code.Substring(offset, length);
            bool Has(string s) => nearby.Contains(s, StringComparison.OrdinalIgnoreCase);
            try
            {
                bool network = NetworkRead.IsMatch(executable), process = ProcessExecution.IsMatch(executable);
                bool dynamic = DynamicExecution.IsMatch(executable), write = FileWrite.IsMatch(executable);
                bool payload = PayloadName.IsMatch(nearby);
                bool steam = Has("steamprocess") || Has("wsock32.dll") && Has("millennium") || Has("SteamKey20260310");
                bool defense = executable.Contains("Add-MpPreference", StringComparison.OrdinalIgnoreCase) ||
                    executable.Contains("ExclusionPath", StringComparison.OrdinalIgnoreCase) || executable.Contains("AttackSurfaceReductionOnlyExclusions", StringComparison.OrdinalIgnoreCase);
                if (network && (dynamic || process && payload && (write || executable.Contains("DownloadFile", StringComparison.OrdinalIgnoreCase) || executable.Contains("urlretrieve", StringComparison.OrdinalIgnoreCase))))
                    signals.Add("邻近代码同时包含网络载荷获取与执行或动态加载，需要核对数据流及来源");
                if (network && (process || dynamic) && steam)
                    signals.Add("下载执行链与 Steam 插件或家族载荷同时出现");
                if (steam && defense) signals.Add("Steam 插件部署同时尝试修改安全排除项");
                if (network && (process || dynamic) && (Has("captcha") || Has("Verification ID") || Has("human verification")))
                    signals.Add("验证码提示与下载执行命令同时出现");
                bool postWithFetch = executable.Contains("fetch", StringComparison.OrdinalIgnoreCase) && Has("POST") &&
                    (executable.Contains("body", StringComparison.OrdinalIgnoreCase) || executable.Contains("FormData", StringComparison.OrdinalIgnoreCase));
                if (CredentialStore.IsMatch(nearby) && FileRead.IsMatch(executable) && (NetworkUpload.IsMatch(executable) || postWithFetch))
                    signals.Add("邻近代码同时读取敏感凭据存储并向网络提交数据，需要核对是否存在外传");
                bool workshop = WorkshopTarget.IsMatch(nearby);
                if (workshop && payload && (FileCopy.IsMatch(executable) || write && (Has("__file__") || Has("GetExecutingAssembly") || Has("GetCurrentMethod"))))
                    signals.Add("邻近代码向工坊或 MOD 路径复制脚本载荷或自身内容，需要核对传播行为");
                if (workshop && RecursiveDelete.IsMatch(executable) && (Has("true") || Has("recursive") || Has("-Recurse") || Has("rmtree")))
                    signals.Add("邻近代码包含工坊或 MOD 内容的递归删除，需要核对破坏性操作");
                if ((executable.Contains("steam_save_mafile", StringComparison.OrdinalIgnoreCase) || executable.Contains("steam_outbox_list", StringComparison.OrdinalIgnoreCase)) &&
                    Has("steam_save_mafile") && Has("steam_outbox_list") && Has("password") &&
                    (Has("/api/v1/plugin/beacon") || Has("proconnector.cfd")))
                    signals.Add("Steam 登录拦截、验证资料发送队列与第三方接收端点同时出现");
            }
            catch (RegexMatchTimeoutException) { /* No threat conclusion can be inferred from a matching timeout. */ }
            if (offset + length == value.Length) break;
        }
        return signals.ToArray();
    }

    private static (string Text, string Code) LexicalViews(string source, string extension)
    {
        extension = extension.ToLowerInvariant();
        char[] text = source.ToCharArray(), code = source.ToCharArray();
        bool hashComments = extension.Length == 0 || extension is ".py" or ".pyw" or ".ps1";
        bool luaComments = extension.Length == 0 || extension is ".lua" or ".luau";
        bool slashComments = extension.Length == 0 || extension is ".js" or ".mjs" or ".cjs" or ".cs" or ".csx";
        void Hide(int start, int end, bool comment)
        {
            for (int k = start; k < end; k++)
                if (source[k] is not '\r' and not '\n') { code[k] = ' '; if (comment) text[k] = ' '; }
        }
        for (int i = 0; i < source.Length;)
        {
            int start = i;
            bool luaComment = luaComments && source.AsSpan(i).StartsWith("--");
            int luaOpen = luaComment ? i + 2 : i;
            if (luaComments && luaOpen < source.Length && source[luaOpen] == '[')
            {
                int afterEquals = luaOpen + 1;
                while (afterEquals < source.Length && source[afterEquals] == '=') afterEquals++;
                if (afterEquals < source.Length && source[afterEquals] == '[')
                {
                    string close = "]" + new string('=', afterEquals - luaOpen - 1) + "]";
                    int end = source.IndexOf(close, afterEquals + 1, StringComparison.Ordinal);
                    i = end < 0 ? source.Length : end + close.Length; Hide(start, i, luaComment); continue;
                }
            }
            bool block = slashComments && source.AsSpan(i).StartsWith("/*");
            bool psBlock = hashComments && source.AsSpan(i).StartsWith("<#");
            if (block || psBlock)
            {
                string close = block ? "*/" : "#>";
                int end = source.IndexOf(close, i + 2, StringComparison.Ordinal);
                i = end < 0 ? source.Length : end + close.Length; Hide(start, i, true); continue;
            }
            if (hashComments && source[i] == '#' || luaComments && source.AsSpan(i).StartsWith("--") || slashComments && source.AsSpan(i).StartsWith("//"))
            {
                while (i < source.Length && source[i] is not '\r' and not '\n') i++;
                Hide(start, i, true); continue;
            }
            if (source[i] is '\'' or '"' or '`')
            {
                char quote = source[i++];
                bool verbatim = start > 0 && source[start - 1] == '@';
                bool triple = i + 1 < source.Length && source[i] == quote && source[i + 1] == quote;
                if (triple)
                {
                    int end = source.IndexOf(new string(quote, 3), i + 2, StringComparison.Ordinal);
                    i = end < 0 ? source.Length : end + 3;
                }
                else while (i < source.Length)
                {
                    if (!verbatim && source[i] == '\\') { i = Math.Min(source.Length, i + 2); continue; }
                    if (source[i++] != quote) continue;
                    if (verbatim && i < source.Length && source[i] == quote) { i++; continue; }
                    break;
                }
                Hide(start, i, false); continue;
            }
            i++;
        }
        return (new string(text), new string(code));
    }

    public static string Redact(string value)
    {
        string result = RedactSecrets(value);
        return result.Length > 4096 ? result[..4096] + "…" : result;
    }

    public static string RedactSecrets(string value)
    {
        try
        {
            string result = QuotedSecret.Replace(value, "${key}${q}[REDACTED]${q}");
            result = Secret.Replace(result, "${key}[REDACTED]");
            result = Query.Replace(result, "${key}[REDACTED]");
            return result;
        }
        catch (RegexMatchTimeoutException) { return "[内容已隐藏]"; }
    }
}
