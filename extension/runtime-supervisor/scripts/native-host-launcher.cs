using System;
using System.Diagnostics;
using System.IO;
using System.Threading;

internal static class NativeHostLauncher
{
    private const string ConfigFileName = "privoke-native-host.config";

    private static int Main()
    {
        try
        {
            string installRoot = AppDomain.CurrentDomain.BaseDirectory;
            string[] config = File.ReadAllLines(Path.Combine(installRoot, ConfigFileName));
            if (config.Length != 3)
            {
                Console.Error.WriteLine("PriVoke native host configuration is invalid.");
                return 2;
            }

            var startInfo = new ProcessStartInfo
            {
                FileName = config[0],
                Arguments = Quote(config[1]),
                WorkingDirectory = installRoot,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            startInfo.EnvironmentVariables["PRIVOKE_REPOSITORY_ROOT"] = config[2];

            using (Process process = Process.Start(startInfo))
            {
                if (process == null)
                {
                    Console.Error.WriteLine("PriVoke Python native host did not start.");
                    return 3;
                }
                Thread input = CopyInBackground(
                    Console.OpenStandardInput(),
                    process.StandardInput.BaseStream,
                    true
                );
                Thread output = CopyInBackground(
                    process.StandardOutput.BaseStream,
                    Console.OpenStandardOutput(),
                    false
                );
                Thread error = CopyInBackground(
                    process.StandardError.BaseStream,
                    Console.OpenStandardError(),
                    false
                );

                process.WaitForExit();
                input.Join(1000);
                output.Join(5000);
                error.Join(5000);
                return process.ExitCode;
            }
        }
        catch (Exception error)
        {
            Console.Error.WriteLine("PriVoke native host failed: " + error.Message);
            return 1;
        }
    }

    private static string Quote(string value)
    {
        return "\"" + value.Replace("\"", "\\\"") + "\"";
    }

    private static Thread CopyInBackground(Stream source, Stream destination, bool closeDestination)
    {
        var thread = new Thread(() =>
        {
            try
            {
                byte[] buffer = new byte[4096];
                int count;
                while ((count = source.Read(buffer, 0, buffer.Length)) > 0)
                {
                    destination.Write(buffer, 0, count);
                    destination.Flush();
                }
            }
            catch (IOException)
            {
                // The browser can close either pipe as soon as the one-shot reply arrives.
            }
            finally
            {
                if (closeDestination)
                {
                    destination.Close();
                }
            }
        });
        thread.IsBackground = true;
        thread.Start();
        return thread;
    }
}
