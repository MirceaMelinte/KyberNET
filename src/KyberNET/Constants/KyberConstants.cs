namespace KyberNET.Constants;

// Numerical constants used throughout Kyber
internal static class KyberConstants
{
    public const int N = 256;
    public const int N_BYTES = N >> 3;
    public const int Q = 3329;
    public const int Q_INV = -62209; // –q^(-1) mod 2^16
    public const int Q_HALF = Q >> 1;
    public const int BARRETT_APPROX = 20159;
    public const int MONT_R2 = 1353;
    public const int SECRET_KEY_LENGTH = N_BYTES;
    public const int ENCODE_SIZE = 3 * N >> 1;
}