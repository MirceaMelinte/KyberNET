namespace KyberNET.Infrastructure
{
    using System;
    using System.Runtime.CompilerServices;

    internal static class Subtle
    {
        // attribute prevents JIT from reintroducing timing variations
        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        internal static int Compare(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
        {
            var length = a.Length;
            var diff = length ^ b.Length;

            var minLen = Math.Min(length, b.Length);

            for (var i = 0; i < minLen; i++)
            {
                diff |= a[i] ^ b[i];
            }

            return diff;
        }

        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        internal static byte[] Select(int condition, byte[] whenEqual, byte[] whenNotEqual)
        {
            var isNonZero = condition | (-condition);
            var mask = (byte)((isNonZero >> 31) & 0xFF);

            var result = new byte[whenEqual.Length];
            
            for (var i = 0; i < result.Length; i++)
            {
                result[i] = (byte)((whenEqual[i] & ~mask) | (whenNotEqual[i] & mask));
            }

            return result;
        }

        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        internal static bool IsAllZero(ReadOnlySpan<byte> data)
        {
            var acc = 0;

            for (var i = 0; i < data.Length; i++)
            {
                acc |= data[i];
            }
            
            return acc == 0;
        }
    }
}