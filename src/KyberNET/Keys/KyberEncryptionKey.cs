namespace KyberNET.Keys;

using Constants;
using Exceptions;
using Infrastructure;

internal sealed class KyberEncryptionKey
    : IKyberPKEKey
{
    public KyberParameter Parameter { get; }

    internal byte[] KeyBytes { get; }
    internal byte[] NttSeed { get; }

    internal KyberEncryptionKey(KyberParameter parameter, byte[] keyBytes, byte[] nttSeed)
    {
        Parameter = parameter;
        KeyBytes = (byte[])keyBytes.Clone();
        NttSeed = (byte[])nttSeed.Clone();

        var coefficients = Encoding.FastByteDecode(KeyBytes, 12);

        for (var i = 0; i < coefficients.Length; i++)
        {
            if (!ModMath.IsModuloOfQ(coefficients[i]))
            {
                throw new InvalidKyberKeyException($"Not modulus of {KyberConstants.Q}");
            }
        }
    }

    public byte[] FullBytes
    {
        get
        {
            var output = new byte[Parameter.EncapsulationKeyLength];
            WriteTo(output);
            return output;
        }
    }

    public void WriteTo(Span<byte> destination)
    {
        KeyBytes.AsSpan().CopyTo(destination);
        NttSeed.AsSpan().CopyTo(destination[KeyBytes.Length..]);
    }

    public static KyberEncryptionKey FromBytes(byte[] bytes)
        => FromBytes(bytes.AsSpan());

    public static KyberEncryptionKey FromBytes(ReadOnlySpan<byte> bytes)
    {
        var keyLength = bytes.Length - KyberConstants.N_BYTES;

        return new KyberEncryptionKey(
            KyberParameter.FindByEncryptionKeySize(bytes.Length),
            bytes[..keyLength].ToArray(),
            bytes[keyLength..].ToArray());
    }
}