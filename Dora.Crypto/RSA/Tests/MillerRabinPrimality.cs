using System.Numerics;

namespace Dora.Crypto.RSA.Tests
{
    public class MillerRabinPrimality : AbstractProbabilisticPrimality
    {
        private static readonly BigInteger ONE = 1;
        private static readonly BigInteger TWO = 2;

        protected override bool Iteration(BigInteger a, BigInteger n)
        {
            BigInteger d = NumberTheory.Gcd(a, n);
            if (d != ONE)
            {
                return false;
            }

            // n-1 = 2^s * d
            BigInteger nm1 = n - ONE;
            int s = 0;
            BigInteger oddD = nm1;
            while ((oddD & 1) == 0)
            {
                oddD >>= 1;
                s++;
            }

            // a^d = 1 (mod n)
            BigInteger x = NumberTheory.ModPow(a, oddD, n);
            if (x == ONE || x == n - ONE)
            {
                return true;
            }

            // E a^(d*2^r) = -1 (mod n)
            for (int r = 1; r < s; r++)
            {
                x = NumberTheory.ModPow(x, TWO, n); // x = x^2 mod n
                if (x == n - ONE)
                {
                    return true;
                }
            }
            return false;
        }
    }
}
