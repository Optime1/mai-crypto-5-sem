using System.Numerics;

namespace Dora.Crypto.RSA.Tests
{
    public class SolovayStrassenPrimality : AbstractProbabilisticPrimality
    {
        private static readonly BigInteger ONE = 1;

        protected override bool Iteration(BigInteger a, BigInteger n)
        {
            BigInteger d = NumberTheory.Gcd(a, n);
            if (d != ONE)
            {
                return false;
            }

            BigInteger exp = (n - ONE) / 2;
            BigInteger left = NumberTheory.ModPow(a, exp, n);

            BigInteger right = NumberTheory.JacobiSymbol(a, n);

            // a^(n - 1)/2 = (a/n) (mod n)

            if (right == -1)
            {
                right = n - ONE;
            }
            return left == right;
        }
    }
}
