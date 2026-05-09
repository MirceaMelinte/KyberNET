namespace KyberNET.Api;

using Constants;
using Keys;

/// <summary>
/// Convenience entry point for ML-KEM-768 operations
/// </summary>
public static class MlKem768
{
    /// <summary>
    /// Generates an ML-KEM-768 key pair
    /// </summary>
    public static KyberKEMKeyPair GenerateKeyPair(IRandomProvider? randomProvider = null)
        => KyberKeyGenerator.Generate(KyberParameter.MlKem768, randomProvider);
}