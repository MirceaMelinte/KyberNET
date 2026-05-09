namespace KyberNET;

using System.Security.Cryptography;

internal sealed class DefaultRandomProvider : IRandomProvider
{
    public static readonly DefaultRandomProvider Instance = new();

    public void FillWithRandom(byte[] buffer) => RandomNumberGenerator.Fill(buffer);
}