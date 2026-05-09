namespace KyberNET.Api;

using Constants;
using Keys;

/// <summary>
/// Convenience entry point for ML-KEM-1024 operations
/// </summary>
public static class MlKem1024
{
    /// <summary>
    /// Generates an ML-KEM-1024 key pair
    /// </summary>
    public static KyberKEMKeyPair GenerateKeyPair(IRandomProvider? randomProvider = null)
        => KyberKeyGenerator.Generate(KyberParameter.MlKem1024, randomProvider);
}