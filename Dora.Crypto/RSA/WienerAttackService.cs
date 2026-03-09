using System;
using System.Collections.Generic;
using System.Numerics;

namespace Dora.Crypto.RSA
{
    public class WienerAttackService
    {
        private static readonly BigInteger ZERO = 0;
        private static readonly BigInteger ONE = 1;
        private static readonly BigInteger TWO = 2;
        private static readonly BigInteger FOUR = 4;

        private readonly IProbabilisticPrimality primalityTest;
        private readonly double minProbability;

        public WienerAttackService(IProbabilisticPrimality primalityTest, double minProbability)
        {
            this.primalityTest = primalityTest;
            this.minProbability = minProbability;
        }

        public record AttackResult(BigInteger d, BigInteger phi, List<Convergent> convergents);
        public record Convergent(BigInteger num, BigInteger den);

        public AttackResult? Attack(BigInteger n, BigInteger e)
        {
            if (n <= 0 || e <= 1 || e >= n)
            {
                throw new ArgumentException("Invalid public key (N, e)");
            }

            List<BigInteger> cf = GetContinuedFractionExpansion(e, n);
            List<Convergent> convergents = GetConvergents(cf);

            BigInteger trace;
            BigInteger disc;
            BigInteger? sqrtDisc;
            BigInteger p, q;

            foreach (var conv in convergents)
            {
                BigInteger kappa = conv.num;
                BigInteger dCand = conv.den;

                if (kappa == 0) continue;

                // ed - k phi = 1
                BigInteger edMinus1 = e * dCand - 1;
                if (edMinus1 % kappa != 0) continue;
                BigInteger phi = edMinus1 / kappa;

                trace = n - phi + 1;
                disc = trace * trace - FOUR * n;
                if (disc < 0) continue;

                sqrtDisc = Isqrt(disc);
                if (sqrtDisc == null || sqrtDisc * sqrtDisc != disc) continue;

                // x² - (N - φ(N) + 1)x + N = 0 root is p and q
                if ((trace + sqrtDisc.Value) % 2 == 0 && (trace - sqrtDisc.Value) % 2 == 0)
                {
                    p = (trace + sqrtDisc.Value) / 2;
                    q = (trace - sqrtDisc.Value) / 2;
                    if (p * q == n)
                    {
                        if (primalityTest.IsProbablyPrime(p, minProbability) && 
                            primalityTest.IsProbablyPrime(q, minProbability))
                        {
                            return new AttackResult(dCand, phi, new List<Convergent>(convergents));
                        }
                    }
                }
            }
            return null;
        }

        /// <summary>
        /// Calculates the continued fraction coefficients for num / den.
        /// </summary>
        private List<BigInteger> GetContinuedFractionExpansion(BigInteger num, BigInteger den)
        {
            List<BigInteger> cf = new List<BigInteger>();
            while (den > 0)
            {
                BigInteger a = num / den;
                cf.Add(a);
                BigInteger remainder = num % den;
                num = den;
                den = remainder;
            }
            return cf;
        }

        /// <summary>
        /// Builds convergents from cf coefficients.
        /// </summary>
        private List<Convergent> GetConvergents(List<BigInteger> cf)
        {
            List<Convergent> convergents = new List<Convergent>();
            if (cf.Count == 0) return convergents;

            BigInteger hPrevPrev = 0;  // h_{-2}
            BigInteger hPrev = 1;       // h_{-1}
            BigInteger kPrevPrev = 1;   // k_{-2}
            BigInteger kPrev = 0;      // k_{-1}

            foreach (BigInteger a in cf)
            {
                BigInteger h = a * hPrev + hPrevPrev;  // hₙ = aₙ*hₙ₋₁ + hₙ₋₂
                BigInteger k = a * kPrev + kPrevPrev;  // kₙ = aₙ*kₙ₋₁ + kₙ₋₂
                convergents.Add(new Convergent(h, k));
                hPrevPrev = hPrev;
                hPrev = h;
                kPrevPrev = kPrev;
                kPrev = k;
            }
            return convergents;
        }

        private static BigInteger? Isqrt(BigInteger n)
        {
            if (n < 0) return null;
            if (n == 0 || n == 1) return n;

            BigInteger x0 = BigInteger.One << (int)((n.GetBitLength() + 1) / 2);
            BigInteger x1 = (n / x0 + x0) / 2;

            while (x1 < x0)
            {
                x0 = x1;
                x1 = (n / x0 + x0) / 2;
            }
            return x0;
        }
    }
}
