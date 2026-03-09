using System.Numerics;

namespace Dora.Crypto.RSA.Tests
{
    public class FermatPrimality : AbstractProbabilisticPrimality
    {
        private static readonly BigInteger ONE = 1;

        protected override bool Iteration(BigInteger a, BigInteger n)
        {
            BigInteger exp = n - ONE;
            BigInteger res = NumberTheory.ModPow(a, exp, n);
            return res == ONE; // a^(n-1) = 1 (mod n)
        }
    }
}
