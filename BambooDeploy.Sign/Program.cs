using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace BambooDeploy.Sign;

static class Program
{
    const string DefaultBase = "https://api.bamboodeploy.com";
    const long DirectMax = 95L * 1024 * 1024;
    static readonly HttpClient Http = new() { Timeout = TimeSpan.FromMinutes(30) };
    static bool Quiet, Json;

    static async Task<int> Main(string[] args)
    {
        try { return await Run(args); }
        catch (BambooException e) { return Fail(e); }
        catch (FileNotFoundException e) { return Fail(new BambooException($"File not found: {e.FileName}", "not_found")); }
        catch (Exception e) { return Fail(new BambooException(e.Message, "error")); }
    }

    static async Task<int> Run(string[] args)
    {
        var (cmd, pos, opt) = Parse(args);
        Quiet = opt.ContainsKey("quiet"); Json = opt.ContainsKey("json");
        if (cmd is null or "help" || opt.ContainsKey("help")) { Console.WriteLine(Help); return 0; }
        var apiBase = (opt.GetValueOrDefault("api-base") ?? Environment.GetEnvironmentVariable("BAMBOO_API_BASE") ?? DefaultBase).TrimEnd('/');
        var key = ResolveKey(opt.GetValueOrDefault("api-key"));
        if (cmd == "config")
        {
            Console.WriteLine($"API base: {apiBase}");
            Console.WriteLine($"API key:  {(key is null ? "(none) set BAMBOO_API_KEY or create .bamboorc" : key[..12] + "..." + key[^4..])}");
            return 0;
        }
        if (key is null) throw new BambooException("No API key. Set BAMBOO_API_KEY, pass --api-key, or put the key in .bamboorc", "no_key");
        Http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", key);
        var timeout = int.Parse(opt.GetValueOrDefault("timeout") ?? "900");
        var interval = int.Parse(opt.GetValueOrDefault("interval") ?? "10");

        switch (cmd)
        {
            case "sign":
            {
                var file = pos.ElementAtOrDefault(0) ?? throw new BambooException("Usage: bamboo-sign sign <file>", "usage");
                var up = await Upload(apiBase, file);
                var id = up["id"]!.GetValue<string>();
                Log($"App id: {id}{(up["duplicate"]?.GetValue<bool>() == true ? " (already uploaded)" : "")}");
                var sign = await Req(HttpMethod.Post, $"{apiBase}/uploads/{id}/sign");
                Log($"Sign job {sign["job_id"]}: {sign["status"]}");
                await WaitForSign(apiBase, id, timeout, interval);
                var dest = opt.GetValueOrDefault("out") ?? file;
                var size = await Download(apiBase, id, dest);
                Log($"Wrote {dest} ({Fmt(size)})");
                Console.WriteLine(Json ? JsonSerializer.Serialize(new { ok = true, app_id = id, job_id = sign["job_id"]?.ToString(), @out = dest, size }) : $"Signed: {dest}");
                return 0;
            }
            case "scan":
            {
                var file = pos.ElementAtOrDefault(0) ?? throw new BambooException("Usage: bamboo-sign scan <file>", "usage");
                var up = await Upload(apiBase, file);
                var id = up["id"]!.GetValue<string>();
                var report = await Report(apiBase, id, timeout);
                var st = await Req(HttpMethod.Get, $"{apiBase}/uploads/{id}");
                var s = st["scan"]!.AsObject();
                var packer = s["packer"]?.ToString(); var yara = s["yara_matches"]?.ToString(); var cs = s["code_signing"]?.ToString();
                var installer = new[] { "NSIS", "Inno", "MSI", "Installer", ".NET", "dotnet", "Electron", "Squirrel", "WiX" };
                var findings = !string.IsNullOrEmpty(yara) || (!string.IsNullOrEmpty(packer) && !installer.Any(p => packer.Contains(p, StringComparison.OrdinalIgnoreCase)));
                if (Json) Console.WriteLine(JsonSerializer.Serialize(new { ok = true, app_id = id, findings, summary = s, report }));
                else
                {
                    Console.WriteLine(report.Trim());
                    Console.WriteLine();
                    Console.WriteLine($"Code signing: {cs ?? "unknown"}{(packer != null ? "\nPacker: " + packer : "")}{(yara != null ? "\nYARA: " + yara : "")}");
                    if (cs != null && cs.Contains("not signed", StringComparison.OrdinalIgnoreCase))
                        Console.WriteLine("This build is unsigned, so Windows SmartScreen will warn users. Sign it with: bamboo-sign sign <file>");
                }
                return findings && opt.ContainsKey("fail-on-findings") ? 5 : 0;
            }
            case "status":
            {
                var id = pos.ElementAtOrDefault(0);
                var r = await Req(HttpMethod.Get, id is null ? $"{apiBase}/uploads?limit={opt.GetValueOrDefault("limit") ?? "20"}" : $"{apiBase}/uploads/{id}");
                if (Json || id != null) Console.WriteLine(r.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
                else foreach (var u in r["uploads"]!.AsArray())
                    Console.WriteLine($"{u!["id"]}  {u["file_name"],-32}  scan:{u["scan"]!["status"],-7} sign:{u["sign"]!["status"]}");
                return 0;
            }
            case "delete":
            {
                var id = pos.ElementAtOrDefault(0) ?? throw new BambooException("Usage: bamboo-sign delete <app-id>", "usage");
                await Req(HttpMethod.Delete, $"{apiBase}/uploads/{id}");
                Console.WriteLine("Deleted");
                return 0;
            }
            default: throw new BambooException($"Unknown command: {cmd}\n\n{Help}", "usage");
        }
    }

    static async Task<JsonObject> Upload(string apiBase, string file)
    {
        var fi = new FileInfo(file);
        if (!fi.Exists) throw new FileNotFoundException("not found", fi.FullName);
        var name = Uri.EscapeDataString(fi.Name);
        Log($"Uploading {fi.Name} ({Fmt(fi.Length)})");
        await using var stream = fi.OpenRead();
        if (fi.Length > DirectMax)
        {
            var init = await Req(HttpMethod.Post, $"{apiBase}/uploads/init?name={name}&size={fi.Length}");
            using var put = new HttpRequestMessage(HttpMethod.Put, init["upload_url"]!.GetValue<string>()) { Content = new StreamContent(stream) };
            put.Content.Headers.ContentLength = fi.Length;
            using var noAuth = new HttpClient { Timeout = TimeSpan.FromMinutes(30) };
            var pr = await noAuth.SendAsync(put);
            if (!pr.IsSuccessStatusCode) throw new BambooException($"Upload failed: HTTP {(int)pr.StatusCode}", "http_error", (int)pr.StatusCode);
            return await Req(HttpMethod.Post, $"{apiBase}/uploads/{init["id"]}/finalize?name={name}");
        }
        var content = new StreamContent(stream);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        content.Headers.ContentLength = fi.Length;
        return await Req(HttpMethod.Post, $"{apiBase}/uploads?name={name}", content);
    }

    static async Task WaitForSign(string apiBase, string id, int timeout, int interval)
    {
        var deadline = DateTime.UtcNow.AddSeconds(timeout);
        string? last = null;
        while (true)
        {
            var s = await Req(HttpMethod.Get, $"{apiBase}/uploads/{id}");
            var sign = s["sign"]!.AsObject();
            var st = sign["status"]?.ToString() ?? "none";
            if (st != last)
            {
                last = st;
                var why = st == "pending" ? (sign["pending_reason"]?.ToString() == "operator_review" ? " (awaiting operator review)" : " (awaiting scan results)") : "";
                Log($"Sign status: {st}{why}");
            }
            if (st == "done") return;
            if (st is "failed" or "denied" or "canceled")
                throw new BambooException($"Sign {st}{(sign["error"] != null ? ": " + sign["error"] : "")}", "sign_" + st, 200, s);
            if (DateTime.UtcNow > deadline)
                throw new BambooException($"Sign did not complete within {timeout}s (last status: {st})", "timeout", 200, s);
            await Task.Delay(interval * 1000);
        }
    }

    static async Task<string> Report(string apiBase, string id, int timeout)
    {
        var deadline = DateTime.UtcNow.AddSeconds(timeout);
        while (true)
        {
            var r = await Http.GetAsync($"{apiBase}/uploads/{id}/report");
            if (r.IsSuccessStatusCode) return await r.Content.ReadAsStringAsync();
            if ((int)r.StatusCode != 409) throw new BambooException($"HTTP {(int)r.StatusCode}", "http_error", (int)r.StatusCode);
            if (DateTime.UtcNow > deadline) throw new BambooException("Scan did not finish in time", "timeout");
            await Task.Delay(5000);
        }
    }

    static async Task<long> Download(string apiBase, string id, string dest)
    {
        using var r = await Http.GetAsync($"{apiBase}/uploads/{id}/download?variant=signed", HttpCompletionOption.ResponseHeadersRead);
        if (!r.IsSuccessStatusCode) throw new BambooException($"Download failed: HTTP {(int)r.StatusCode}", "http_error", (int)r.StatusCode);
        var full = Path.GetFullPath(dest);
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        var tmp = full + ".bamboo-tmp";
        await using (var fs = File.Create(tmp)) await r.Content.CopyToAsync(fs);
        File.Move(tmp, full, true);
        return new FileInfo(full).Length;
    }

    static async Task<JsonObject> Req(HttpMethod method, string url, HttpContent? content = null)
    {
        using var req = new HttpRequestMessage(method, url) { Content = content };
        using var res = await Http.SendAsync(req);
        var text = await res.Content.ReadAsStringAsync();
        JsonObject body;
        try { body = JsonNode.Parse(text)!.AsObject(); } catch { body = new JsonObject { ["error"] = text[..Math.Min(300, text.Length)] }; }
        if (!res.IsSuccessStatusCode)
        {
            var err = body["error"]?.ToString();
            var code = err == "premium_required" ? "premium_required" : err == "connections_required" ? "connections_required" : (int)res.StatusCode == 401 ? "unauthorized" : "http_error";
            throw new BambooException(body["message"]?.ToString() ?? err ?? $"HTTP {(int)res.StatusCode}", code, (int)res.StatusCode, body);
        }
        return body;
    }

    static string? ResolveKey(string? explicitKey)
    {
        if (!string.IsNullOrEmpty(explicitKey)) return explicitKey;
        var env = Environment.GetEnvironmentVariable("BAMBOO_API_KEY");
        if (!string.IsNullOrEmpty(env)) return env;
        foreach (var dir in new[] { Directory.GetCurrentDirectory(), Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) })
        {
            var f = Path.Combine(dir, ".bamboorc");
            if (!File.Exists(f)) continue;
            var m = System.Text.RegularExpressions.Regex.Match(File.ReadAllText(f), @"(bd_live_[0-9a-f]+)", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            if (m.Success) return m.Groups[1].Value;
        }
        return null;
    }

    static (string? cmd, List<string> pos, Dictionary<string, string> opt) Parse(string[] args)
    {
        var pos = new List<string>(); var opt = new Dictionary<string, string>();
        var valued = new HashSet<string> { "out", "timeout", "interval", "limit", "api-key", "api-base" };
        for (var i = 0; i < args.Length; i++)
        {
            if (args[i].StartsWith("--"))
            {
                var k = args[i][2..];
                opt[k] = valued.Contains(k) && i + 1 < args.Length ? args[++i] : "true";
            }
            else pos.Add(args[i]);
        }
        var cmd = pos.Count > 0 ? pos[0] : null;
        if (pos.Count > 0) pos.RemoveAt(0);
        return (cmd, pos, opt);
    }

    static int Fail(BambooException e)
    {
        var code = e.Code switch { "premium_required" => 2, "connections_required" => 3, "timeout" => 4, _ => 1 };
        if (Json) Console.WriteLine(JsonSerializer.Serialize(new { ok = false, error = e.Code, message = e.Message }));
        else
        {
            Console.Error.WriteLine($"Error: {e.Message}");
            if (e.Code == "premium_required") Console.Error.WriteLine("Upgrade at https://www.bamboodeploy.com/dashboard/#billing");
            if (e.Code == "connections_required") Console.Error.WriteLine("Verify your publisher connections at https://www.bamboodeploy.com/dashboard/");
            if (e.Code == "timeout" && e.Body?["sign"]?["pending_reason"]?.ToString() == "operator_review")
                Console.Error.WriteLine("The job is waiting for operator review. Re-run once approved, or ask Bamboo to enable Auto-sign on your account so clean builds sign without review.");
        }
        return code;
    }

    static void Log(string m) { if (!Quiet && !Json) Console.Error.WriteLine(m); }
    static string Fmt(long n) => n >= 1048576 ? $"{n / 1048576.0:F1} MB" : n >= 1024 ? $"{n / 1024} KB" : $"{n} B";

    const string Help = @"bamboo-sign  Scan and code-sign Windows binaries via Bamboo Deploy

Usage:
  bamboo-sign sign <file> [--out <path>] [--timeout 900] [--interval 10]
  bamboo-sign scan <file> [--json] [--fail-on-findings]
  bamboo-sign status [app-id]
  bamboo-sign delete <app-id>
  bamboo-sign config

Options:
  --api-key <key>   API key (else BAMBOO_API_KEY env or .bamboorc)
  --out <path>      Where to write the signed file (default: replace input)
  --timeout <s>     Max seconds to wait for signing (default 900)
  --interval <s>    Poll interval in seconds (default 10)
  --json            Machine-readable output
  --quiet           No progress output

Exit codes: 0 ok, 1 error, 2 premium required, 3 verification required, 4 timeout or pending review, 5 scan findings";
}

class BambooException(string message, string code, int status = 0, JsonObject? body = null) : Exception(message)
{
    public string Code { get; } = code;
    public int Status { get; } = status;
    public JsonObject? Body { get; } = body;
}
