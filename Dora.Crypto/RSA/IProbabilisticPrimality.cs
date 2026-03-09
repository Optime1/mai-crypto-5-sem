using System.Numerics;

namespace Dora.Crypto.RSA
{
    public interface IProbabilisticPrimality
    {
        /// <summary>
        /// Checks whether n is probably prime with probability >= minProb.
        /// </summary>
        /// <param name="n">test value (BigInteger > 1)</param>
        /// <param name="minProb">minimum probability of prime in [0.5, 1)</param>
        /// <returns>true if n is likely prime, otherwise false</returns>
        bool IsProbablyPrime(BigInteger n, double minProb);
    }
}
