namespace KyberNET.Api
{
    using Constants;
    using Keys;

    /// <summary>
    /// Convenience entry point for ML-KEM-512 operations
    /// </summary>
    public static class MlKem512
    {
        /// <summary>
        /// Generates an ML-KEM-512 key pair
        /// </summary>
        public static KyberKEMKeyPair GenerateKeyPair(IRandomProvider? randomProvider = null)
            => KyberKeyGenerator.Generate(KyberParameter.MlKem512, randomProvider);
    }
}