using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;

// Built with the Windows .NET Framework compiler. No cmd.exe or PowerShell in the launch path.
internal static class PqcLauncher
{
    private const string RuntimeSha256 = "d702daa815eabbff763c7d3808e235cf031cf2ca70211b56847bc72f51e240e5";

    // Windows CRT quoting: preserve empty arguments, quotes and trailing backslashes.
    private static string Quote(string argument)
    {
        StringBuilder result = new StringBuilder("\"");
        int slashes = 0;
        foreach (char value in argument)
        {
            if (value == '\\') { slashes++; continue; }
            if (value == '"') result.Append('\\', slashes * 2 + 1);
            else result.Append('\\', slashes);
            result.Append(value);
            slashes = 0;
        }
        result.Append('\\', slashes * 2);
        result.Append('"');
        return result.ToString();
    }

    private static int Failure(string[] arguments, string code, string message)
    {
        // All fields here are fixed internal strings. Never print caller arguments or exceptions.
        if (Array.IndexOf(arguments, "--json") >= 0)
            Console.Error.WriteLine("{\"ok\":false,\"error\":{\"code\":\"" + code + "\",\"message\":\"" + message + "\"}}");
        else Console.Error.WriteLine("PQC [" + code + "]: " + message);
        return 1;
    }

    private static int Main(string[] arguments)
    {
        ConsoleCancelEventHandler interrupt = delegate(object sender, ConsoleCancelEventArgs e) { e.Cancel = true; };
        try
        {
            string home = AppDomain.CurrentDomain.BaseDirectory;
            string runtime = Path.Combine(home, "runtime", "node.exe");
            string entry = Path.Combine(home, "tool", "bin", "pqc.mjs");
            if (!File.Exists(runtime) || !File.Exists(entry))
                return Failure(arguments, "PORTABLE_INCOMPLETE", "Portable package is incomplete; extract the entire archive.");
            // Deny writes/deletes while checking and running this copy of the runtime.
            using (FileStream binary = File.Open(runtime, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (SHA256 sha = SHA256.Create())
            {
                string actual = BitConverter.ToString(sha.ComputeHash(binary)).Replace("-", "").ToLowerInvariant();
                if (!String.Equals(actual, RuntimeSha256, StringComparison.Ordinal))
                    return Failure(arguments, "RUNTIME_INTEGRITY", "Bundled Node runtime integrity check failed.");
                StringBuilder forwarded = new StringBuilder(Quote(entry));
                foreach (string argument in arguments) forwarded.Append(' ').Append(Quote(argument));
                ProcessStartInfo start = new ProcessStartInfo(runtime, forwarded.ToString());
                start.UseShellExecute = false;
                start.WorkingDirectory = Environment.CurrentDirectory;
                // Do not load arbitrary preloads or provider configuration inherited from the caller.
                foreach (string name in new string[] { "NODE_OPTIONS", "NODE_PATH", "OPENSSL_CONF", "OPENSSL_MODULES", "OPENSSL_ENGINES" })
                    start.EnvironmentVariables.Remove(name);
                Console.CancelKeyPress += interrupt;
                using (Process child = Process.Start(start))
                {
                    child.WaitForExit();
                    return child.ExitCode;
                }
            }
        }
        catch { return Failure(arguments, "PORTABLE_LAUNCH_FAILED", "Unable to start the bundled toolkit; check extraction and permissions."); }
        finally { Console.CancelKeyPress -= interrupt; }
    }
}
