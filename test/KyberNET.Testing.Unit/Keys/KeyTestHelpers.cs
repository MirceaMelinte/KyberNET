namespace KyberNET.Testing.Unit.Keys;

internal static class KeyTestHelpers
{
    internal static byte[] MakeValidKeyBytes(int length) => new byte[length];

    internal static byte[] MakeInvalidKeyBytes(int length)
    {
        var bytes = new byte[length];
        Array.Fill(bytes, (byte)0xFF);

        return bytes;
    }
}