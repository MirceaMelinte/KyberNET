namespace KyberNET.Infrastructure
{
    using Constants;
    
    public static class ModMath
    {
        /// <summary>
        /// Maps <paramref name="n"/> into [0, 2 · Q]
        /// Simple multiply-shift-subtract formula
        /// </summary>
        /// <param name="n">|n| is assumed to be < 2^26 · Q </param>
        public static int BarrettReduce(int n)
        {
            var q = (n * KyberConstants.BARRETT_APPROX) >> 26;
            return n - (q * KyberConstants.Q);
        }

        /// <summary>
        /// Lazy Montgomery reduction algorithm using the "low 16 bits trick"
        /// </summary>
        public static int MontgomeryReduce(int t)
        {
            unchecked // to match overflow semantics from the spec
            {
                var m = (t * KyberConstants.Q_INV) & 0xFFFF; // low 16 bits
                var u = (t + m * KyberConstants.Q) >> 16;
                
                return u; // 0 <= u < 2 · Q
            }
        }

        /// <summary>
        /// Converts a valid integer into the Montgomery form
        /// </summary>
        /// <returns>aR mod Q</returns>
        public static int ToMontgomeryForm(int a) => MontgomeryReduce(a * KyberConstants.MONT_R2);

        /// <summary>
        /// Single montgomery multiplication of 2 32-bit integers
        /// </summary>
        /// <returns>abR^(-1) mod Q</returns>
        public static int ProductOf(int a, int b) => MontgomeryReduce(a * b);
        
        /// <summary>
        /// 26-bit Barrett shortcut
        /// Checks if <paramref name="n"/> is already reduced, in other words is in range [0, Q)
        /// Used during key parsing to reject invalid coefficients
        /// </summary>
        public static bool IsModuloOfQ(int n) => ((n * KyberConstants.BARRETT_APPROX) >> 26) == 0;
    }
}