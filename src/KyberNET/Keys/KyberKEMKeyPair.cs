namespace KyberNET.Keys;

/// <summary>
/// An ML-KEM key pair consisting of an encapsulation key and a decapsulation key
/// </summary>
public sealed class KyberKEMKeyPair(KyberEncapsulationKey encapsulationKey, KyberDecapsulationKey decapsulationKey)
    : IDisposable
{
    private bool disposed;

    /// <summary>
    /// The public encapsulation key
    /// </summary>
    public KyberEncapsulationKey EncapsulationKey { get; } = encapsulationKey;

    /// <summary>
    /// The private decapsulation key
    /// </summary>
    public KyberDecapsulationKey DecapsulationKey { get; } = decapsulationKey;

    public void Dispose()
    {
        if (!disposed)
        {
            DecapsulationKey.Dispose();
            
            disposed = true;
        }
    }
}
