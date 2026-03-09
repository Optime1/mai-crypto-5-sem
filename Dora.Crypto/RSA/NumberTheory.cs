using System;
using System.Numerics;

namespace Dora.Crypto.RSA
{
    public static class NumberTheory
    {
        public static BigInteger Gcd(BigInteger a, BigInteger b)
        {
            a = BigInteger.Abs(a);
            b = BigInteger.Abs(b);
            while (b != 0)
            {
                BigInteger temp = b;
                b = a % b;
                a = temp;
            }
            return a;
        }

        public static BigInteger[] ExtendedGcd(BigInteger a, BigInteger b)
        {
            a = BigInteger.Abs(a);
            b = BigInteger.Abs(b);
            if (b == 0)
            {
                return new BigInteger[] { a, 1, 0 };
            }
            BigInteger[] previous = ExtendedGcd(b, a % b);
            BigInteger x = previous[2];
            BigInteger y = previous[1] - (a / b) * previous[2];
            return new BigInteger[] { previous[0], x, y };
        }

        public static BigInteger ModPow(BigInteger a, BigInteger exponent, BigInteger modulus)
        {
            if (modulus == 0)
            {
                throw new ArgumentException("Modulus cannot be zero");
            }
            a = BigInteger.Abs(a % modulus);
            BigInteger result = 1;
            while (exponent > 0)
            {
                if ((exponent & 1) == 1)
                {
                    result = (result * a) % modulus;
                }
                a = (a * a) % modulus;
                exponent >>= 1;
            }
            return result;
        }

        public static BigInteger ModInverse(BigInteger a, BigInteger m)
        {
            if (m == 0)
            {
                throw new ArithmeticException("Modulus must not be zero");
            }

            BigInteger[] gcdResult = ExtendedGcd(a, m);
            BigInteger gcd = gcdResult[0];
            BigInteger x = gcdResult[1];

            if (gcd != 1)
            {
                throw new ArithmeticException("Inverse does not exist: gcd(a, m) != 1");
            }

            BigInteger inverse = x % m;
            if (inverse.Sign < 0)
            {
                inverse += m;
            }

            return inverse;
        }

        public static BigInteger JacobiSymbol(BigInteger a, BigInteger n)
        {
            if (n <= 0 || n % 2 == 0 || n == 1)
            {
                throw new ArgumentException("n must be positive odd integer > 1");
            }

            if (BigInteger.GreatestCommonDivisor(a, n) != 1)
            {
                return 0;
            }

            BigInteger r = 1;

            if (a < 0)
            {
                a = -a;
                if (n % 4 == 3)
                {
                    r = -r;
                }
            } // change sign if n = 3 (mod 4)

            while (a != 0)
            {
                int t = 0;
                while (a % 2 == 0)
                {
                    t++;
                    a /= 2;
                } //

                if (t % 2 != 0)
                {
                    BigInteger bMod8 = n % 8;
                    if (bMod8 == 3 || bMod8 == 5)
                    {
                        r = -r;
                    }
                } //(2/n) = -1 if n ≡ 3, 5 (mod 8)

                if (a % 4 == 3 && n % 4 == 3)
                {
                    r = -r;
                } // if a and n = 3 (mod 4)  change sign

                BigInteger temp = a;
                a = n % temp;
                n = temp;
            }

            return r;
        }

        public static BigInteger LegendreSymbol(BigInteger a, BigInteger p)
        {
            if (p <= 2 || !IsPrime(p))
            {
                throw new ArgumentException("p must be a positive prime");
            }

            return JacobiSymbol(a, p);
        }

        public static bool IsPrime(BigInteger n)
        {
            if (n < 2) return false;
            if (n == 2 || n == 3) return true;
            if (n % 2 == 0 || n % 3 == 0) return false;
            for (BigInteger i = 5; i * i <= n; i += 6)
            {
                if (n % i == 0 || n % (i + 2) == 0) return false;
            }
            return true;
        }
    }
}
