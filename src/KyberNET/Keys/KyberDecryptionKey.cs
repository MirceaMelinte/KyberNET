namespace KyberNET.Keys;

using Constants;
using Exceptions;
using Infrastructure;

internal sealed class KyberDecryptionKey
    : IKyberPKEKey, IDisposable
{
    private bool disposed;

    public KyberParameter Parameter { get; }

    internal byte[] KeyBytes { get; }

    internal KyberDecryptionKey(KyberParameter parameter, byte[] keyBytes)
    {
        Parameter = parameter;
        KeyBytes = (byte[])keyBytes.Clone();

        var coefficients = Encoding.FastByteDecode(KeyBytes, 12);

        for (var i = 0; i < coefficients.Length; i++)
        {
            if (!ModMath.IsModuloOfQ(coefficients[i]))
            {
                throw new InvalidKyberKeyException($"Not modulus of {KyberConstants.Q}");
            }
        }
    }

    public byte[] FullBytes => (byte[])KeyBytes.Clone();

    public void WriteTo(Span<byte> destination) => KeyBytes.AsSpan().CopyTo(destination);

    public static KyberDecryptionKey FromBytes(byte[] bytes)
        => FromBytes(bytes.AsSpan());

    public static KyberDecryptionKey FromBytes(ReadOnlySpan<byte> bytes)
        => new(KyberParameter.FindByDecryptionKeySize(bytes.Length), bytes.ToArray());

    public void Dispose()
    {
        if (!disposed)
        {
            Array.Clear(KeyBytes, 0, KeyBytes.Length);
            
            disposed = true;
        }
    }
}