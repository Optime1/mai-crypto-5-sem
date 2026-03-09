using System;
using System.Numerics;
using System.Security.Cryptography;

namespace Dora.Crypto.RSA
{
    public abstract class AbstractProbabilisticPrimality : IProbabilisticPrimality
    {
        private static readonly Random Random = new RandomNumberGeneratorWrapper();
        private static readonly BigInteger ONE = 1;
        private static readonly BigInteger TWO = 2;
        private static readonly BigInteger THREE = 3;

        public bool IsProbablyPrime(BigInteger n, double minProb)
        {
            if (minProb < 0.5 || minProb >= 1)
            {
                throw new ArgumentException("minProb must be in [0.5, 1)");
            }

            if (n <= 0 || n == ONE)
            {
                return false;
            }
            if (n == TWO || n == THREE)
            {
                return true;
            }
            if ((n & 1) == 0)
            {
                return false;
            }

            // 1/2^k <= errorProb
            double errorProb = 1.0 - minProb;
            int k = (int)Math.Ceiling(Math.Log(1.0 / errorProb) / Math.Log(2.0));

            for (int i = 0; i < k; i++)
            {
                BigInteger a;
                do
                {
                    a = GenerateRandomBigInteger((int)(n.GetBitLength() - 1));
                } while (a < TWO || a >= n - TWO);
                
                if (!Iteration(a, n))
                {
                    return false;
                }
            }
            return true;
        }

        /// <summary>
        /// Customized behavior of a single test iteration.
        /// Must return true if witness a passes the test (n is probably a prime for this a),
        /// false if a is a witness to the composite.
        /// </summary>
        /// <param name="a">witness</param>
        /// <param name="n">is the number being tested</param>
        /// <returns>true if it passes</returns>
        protected abstract bool Iteration(BigInteger a, BigInteger n);

        private BigInteger GenerateRandomBigInteger(int bitLength)
        {
            if (bitLength <= 0) return 0;
            
            byte[] bytes = new byte[(bitLength + 7) / 8];
            Random.NextBytes(bytes);
            
            // Clear bits beyond bitLength
            int excessBits = bytes.Length * 8 - bitLength;
            if (excessBits > 0)
            {
                bytes[0] &= (byte)(0xFF >> excessBits);
            }
            
            // Ensure positive
            bytes[bytes.Length - 1] &= 0x7F;
            
            return new BigInteger(bytes);
        }
    }

    internal class RandomNumberGeneratorWrapper : Random
    {
        private readonly RandomNumberGenerator _rng = RandomNumberGenerator.Create();

        public override void NextBytes(byte[] buffer)
        {
            _rng.GetBytes(buffer);
        }
    }
}
