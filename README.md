# BambooDeploy.Sign

Scan and code-sign Windows `.exe` and `.msi` files from `dotnet publish`, MSBuild, or any build script. No certificate to buy, no hardware token, no Windows VM. Files are signed with the Bamboo Deploy certificate after a malware scan, so the publisher shown to users is ours, not yours.

```bash
dotnet tool install -g BambooDeploy.Sign
bamboo-sign sign bin/Release/net8.0/publish/MyApp.exe
```

Upload, sign, download the signed file in place. Windows, macOS, and Linux.

## Setup

1. Create an API key in the [Bamboo Deploy dashboard](https://www.bamboodeploy.com/dashboard/) under **API Keys**.
2. Export it as `BAMBOO_API_KEY`, or put `BAMBOO_API_KEY=bd_live_...` in a `.bamboorc` file in the project or home directory.
3. Uploads and scans work on the free tier. Signing needs a Premium subscription.

## Sign after publish

Add a target to the `.csproj` so every `dotnet publish` of a Release build comes out signed:

```xml
<Target Name="BambooSign" AfterTargets="Publish" Condition="'$(Configuration)' == 'Release' And '$(BAMBOO_API_KEY)' != ''">
  <Exec Command="bamboo-sign sign &quot;$(PublishDir)$(AssemblyName).exe&quot;" />
</Target>
```

Works with WPF, WinForms, WinUI, console apps, and `PublishSingleFile`. For an installer built afterwards (Inno Setup, WiX, MSIX), sign the installer too in the same way.

## Commands

```
bamboo-sign sign <file>... [--out path] [--timeout 900] sign, replace in place by default
bamboo-sign scan <file> [--json] [--fail-on-findings]  free: scan report + SmartScreen readiness
bamboo-sign status [app-id]                            list uploads, or one app's scan + sign state
bamboo-sign delete <app-id>
bamboo-sign config                                     show which key and API base are in use
```

Several files at once: `bamboo-sign sign dist/app.exe "dist/*.dll"`. Each file is signed, and with `--out` they go into that folder. Wildcards work in any shell, including PowerShell and cmd. Status checks and downloads retry on network errors.

Exit codes: `0` ok, `1` error, `2` Premium required, `3` publisher verification required, `4` timeout or waiting for review, `5` scan findings (with `--fail-on-findings`).

## CI

Install the tool in the job, then run it after publish:

```yaml
- run: dotnet tool install -g BambooDeploy.Sign
- run: bamboo-sign sign ./publish/MyApp.exe
  env:
    BAMBOO_API_KEY: ${{ secrets.BAMBOO_API_KEY }}
```

More: [developer docs](https://www.bamboodeploy.com/docs/).

## License

MIT
