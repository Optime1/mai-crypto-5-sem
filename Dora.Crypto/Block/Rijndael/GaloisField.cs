namespace Dora.Crypto.Block.Rijndael;

using System;
using System.Collections.Generic;
using System.Linq;

/// <summary>
/// Арифметика в поле Галуа GF(2^8).
/// </summary>
public sealed class GaloisField
{
    /// <summary>
    /// Возвращает степень полинома в GF(2^8).
    /// </summary>
    public int Degree(byte f) => Degree((ulong)f);

    /// <summary>
    /// Сложение двух полиномов в GF(2^8).
    /// </summary>
    public byte Add(byte a, byte b) => (byte)(a ^ b);

    /// <summary>
    /// Умножение двух полиномов в GF(2^8) по модулю irreducible polynomial <paramref name="mod"/>.
    /// </summary>
    public byte MulMod(byte a, byte b, short mod)
    {
        if (!Irreducible(mod))
            throw new ArgumentException("Modulus may not be reducible");
        return MulModUnchecked(a, b, mod);
    }

    /// <summary>
    /// Умножение двух полиномов в GF(2^8) по модулю без проверки на неприводимость.
    /// </summary>
    internal byte MulModUnchecked(byte a, byte b, short mod)
        => (byte)MulMod(a, b, (ulong)mod);

    /// <summary>
    /// Возвращает мультипликативный обратный элемент полинома в GF(2^8) по модулю <paramref name="mod"/>.
    /// </summary>
    public byte Inv(byte f, short mod)
    {
        if (!Irreducible(mod))
            throw new ArgumentException("Modulus may not be reducible");
        return (byte)Inv(f, (ulong)mod);
    }

    /// <summary>
    /// Возвращает мультипликативный обратный элемент без проверки на неприводимость.
    /// </summary>
    internal byte InvUnchecked(byte f, short mod)
        => (byte)Inv(f, (ulong)mod);

    /// <summary>
    /// Проверяет, является ли полином степени 8 неприводимым в GF(2^8).
    /// </summary>
    public bool Irreducible(short f) => Irreducible((ulong)f);

    /// <summary>
    /// Возвращает коллекцию неприводимых полиномов степени 8 в GF(2^8).
    /// </summary>
    public ICollection<short> Irreducibles()
        => Irreducibles(8).Select(x => (short)x).ToList();

    /// <summary>
    /// Разлагает полином в GF(2^N) на неприводимые множители.
    /// </summary>
    public ICollection<ulong> Factorize(ulong f)
    {
        if (f == 0) throw new ArgumentException("Cannot factor zero");
        if (f == 1) return Array.Empty<ulong>();

        List<ulong> factors = new();
        int maxDegree = Degree(f) / 2;

        for (int d = 1; d <= maxDegree; d++)
        {
            foreach (ulong p in Irreducibles(d))
            {
                DivMod divMod;
                while ((divMod = DivMod(f, p)).Remainder == 0)
                {
                    factors.Add(p);
                    f = divMod.Quotient;
                }
            }
        }

        if (f > 1)
            factors.Add(f);

        return factors;
    }

    #region Implementation

    private int Degree(ulong f) => 63 - LeadingZeroCount(f);

    private static int LeadingZeroCount(ulong value)
    {
        if (value == 0) return 64;
        int count = 0;
        if ((value & 0xFFFFFFFF00000000) == 0) { count += 32; value <<= 32; }
        if ((value & 0xFFFF000000000000) == 0) { count += 16; value <<= 16; }
        if ((value & 0xFF00000000000000) == 0) { count += 8; value <<= 8; }
        if ((value & 0xF000000000000000) == 0) { count += 4; value <<= 4; }
        if ((value & 0xC000000000000000) == 0) { count += 2; value <<= 2; }
        if ((value & 0x8000000000000000) == 0) { count += 1; }
        return count;
    }

    private ulong Mul(ulong a, ulong b)
    {
        ulong p = 0;
        for (int i = 0; i < 64; i++)
        {
            if ((b & 1) == 1) p ^= a;
            b >>= 1;
            a <<= 1;
        }
        return p;
    }

    private ulong MulMod(ulong a, ulong b, ulong mod) => DivMod(Mul(a, b), mod).Remainder;

    private DivMod DivMod(ulong a, ulong b)
    {
        ulong q = 0, r = a;
        while (Degree(r) >= Degree(b))
        {
            int lead = Degree(r) - Degree(b);
            q ^= 1UL << lead;
            r ^= b << lead;
        }
        return new DivMod(q, r);
    }

    private readonly record struct DivMod(ulong Quotient, ulong Remainder);

    private EGcd EGcd(ulong a, ulong b)
    {
        ulong r0 = a, r = b;
        ulong s0 = 1, s = 0;
        ulong t0 = 0, t = 1;

        while (r != 0)
        {
            ulong quotient = DivMod(r0, r).Quotient;
            ulong temp;

            temp = r0;
            r0 = r;
            r = temp ^ Mul(quotient, r);

            temp = s0;
            s0 = s;
            s = temp ^ Mul(quotient, s);

            temp = t0;
            t0 = t;
            t = temp ^ Mul(quotient, t);
        }

        return new EGcd(r0, s0, t0);
    }

    private readonly record struct EGcd(ulong Gcd, ulong A, ulong B);

    private ulong Inv(ulong f, ulong mod)
    {
        var result = EGcd(f, mod);
        if (result.Gcd != 1)
            throw new ArgumentException("Inverse element does not exist");
        return result.A;
    }

    private bool Irreducible(ulong f)
    {
        int n = Degree(f);
        if (n <= 0) return false;
        if (n == 1) return true;

        const int x = 0b10;
        int k = n;

        for (int p = 2; p * p <= k; p++)
        {
            if (k % p != 0) continue;

            ulong h = Pow2Mod(x, n / p, f) ^ x;
            ulong g = EGcd(f, h).Gcd;
            if (g != 1) return false;

            while (k % p == 0) k /= p;
        }

        if (k > 1)
        {
            ulong h = Pow2Mod(x, n / k, f) ^ x;
            ulong g = EGcd(f, h).Gcd;
            if (g != 1) return false;
        }

        return Pow2Mod(x, n, f) == x;
    }

    private ulong Pow2Mod(ulong f, int exp, ulong mod)
    {
        ulong result = f;
        for (int i = 0; i < exp; i++)
            result = MulMod(result, result, mod);
        return result;
    }

    private IEnumerable<ulong> Irreducibles(int degree)
        => Enumerable.Range(0, 1 << degree)
            .Select(i => (ulong)(1UL << degree) | (ulong)i)
            .Where(Irreducible);

    #endregion
}
