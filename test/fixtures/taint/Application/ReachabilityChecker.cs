public static class ReachabilityChecker
{
    public static async Task<string> ProbeAsync(string host, CancellationToken cancellationToken)
    {
        var info = BuildStartInfo(host);
        using var process = Process.Start(info);
        await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
        return await process.StandardOutput.ReadToEndAsync().ConfigureAwait(false);
    }

    private static ProcessStartInfo BuildStartInfo(string host)
    {
        return new ProcessStartInfo
        {
            FileName = "cmd.exe",
            Arguments = $"/c ping -n 1 -w 1000 {host}",
            UseShellExecute = false,
        };
    }
}
