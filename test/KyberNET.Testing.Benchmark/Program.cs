namespace KyberNET.Testing.Benchmark;

using System.Diagnostics;
using Hashing;

public static class Program
{
    public static async Task Main(string[] args)
    {
        static string ToHex(byte[] data)
        {
            char[] c = new char[data.Length * 2];
            for (int i = 0; i < data.Length; i++)
            {
                byte b = data[i];
                c[i * 2] = GetHexNibble(b >> 4);
                c[i * 2 + 1] = GetHexNibble(b & 0xF);
            }
            return new string(c);
            static char GetHexNibble(int v) => (char)(v < 10 ? '0' + v : 'a' + (v - 10));
        }

        static void Expect(string label, string expectedHex, string actualHex, ref int failures)
        {
            if (!string.Equals(expectedHex, actualHex, StringComparison.Ordinal))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[FAIL] {label}\n  expected: {expectedHex}\n  actual:   {actualHex}");
                Console.ResetColor();
                failures++;
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"[PASS] {label} = {actualHex}");
                Console.ResetColor();
            }
        }

        int failures = 0;

        // SHAKE128 (empty input, 16 bytes)
        {
            const string expected = "7f9c2ba4e88f827d616045507605853e";

            var api = new SHAKE128(); // default OutputLength = 16
            var digestHex = ToHex(api.Digest());
            Expect("SHAKE128 Digest()", expected, digestHex, ref failures);

            var streamHex = ToHex(api.Stream().NextBytes(api.OutputLength));
            Expect("SHAKE128 Stream().NextBytes()", expected, streamHex, ref failures);

            HashInputStream his = SHAKE128.NewInputStream();
            var hisHex = ToHex(his.Close().NextBytes(api.OutputLength));
            Expect("SHAKE128 NewInputStream()->Close()->NextBytes()", expected, hisHex, ref failures);

            // quick extendability ping (no KAT compare, just length & preview)
            var more = api.Stream().NextBytes(64);
            Console.WriteLine($"SHAKE128 extendable OK (64 bytes). First 16: {ToHex(more[..16])}");
        }

        // SHAKE256 (empty input, 32 bytes)
        {
            const string expected = "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f";

            var api = new SHAKE256(); // default OutputLength = 32
            var digestHex = ToHex(api.Digest());
            Expect("SHAKE256 Digest()", expected, digestHex, ref failures);

            var streamHex = ToHex(api.Stream().NextBytes(api.OutputLength));
            Expect("SHAKE256 Stream().NextBytes()", expected, streamHex, ref failures);

            HashInputStream his = SHAKE256.NewInputStream();
            var hisHex = ToHex(his.Close().NextBytes(api.OutputLength));
            Expect("SHAKE256 NewInputStream()->Close()->NextBytes()", expected, hisHex, ref failures);

            // quick extendability ping
            var more = api.Stream().NextBytes(96);
            Console.WriteLine($"SHAKE256 extendable OK (96 bytes). First 16: {ToHex(more[..16])}");
        }

        Console.WriteLine();
        if (failures == 0)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("All smoke tests passed ✅");
            Console.ResetColor();
            Environment.Exit(0);
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"{failures} smoke test(s) failed ❌");
            Console.ResetColor();
            Environment.Exit(1);
        }

        await Task.CompletedTask;
    }
}