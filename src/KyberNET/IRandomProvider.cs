namespace KyberNET
{
    /// <summary>
    /// Provides cryptographically secure random bytes for key generation and encapsulation
    /// </summary>
    public interface IRandomProvider
    {
        /// <summary>
        /// Fills the entire buffer with cryptographically secure random bytes
        /// </summary>
        void FillWithRandom(byte[] buffer);
    }
}