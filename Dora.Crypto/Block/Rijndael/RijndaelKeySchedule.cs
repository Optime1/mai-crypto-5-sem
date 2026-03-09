namespace Dora.Crypto.Block.Rijndael;

/// <summary>
/// Расписание ключей для алгоритма Rijndael.
/// </summary>
public sealed class RijndaelKeySchedule : IKeySchedule
{
    private readonly RijndaelParameters _parameters;

    public RijndaelKeySchedule(RijndaelParameters parameters)
    {
        _parameters = parameters ?? throw new ArgumentNullException(nameof(parameters));
    }

    public byte[][] RoundKeys(byte[] key)
    {
        if (key == null) throw new ArgumentNullException(nameof(key));

        var keySize = _parameters.GetKeySize();
        var blockSize = _parameters.GetBlockSize();

        if (key.Length != keySize.Bytes())
            throw new ArgumentException("Invalid key size");

        /* https://en.wikipedia.org/wiki/AES_key_schedule#The_key_schedule */

        // Длина ключа в 32-битных словах.
        int n = keySize.Words();
        // Длина блока в 32-битных словах.
        int b = blockSize.Words();
        // Количество раундовых ключей.
        int r = _parameters.Rounds() + 1;
        // 32-битные слова расширенного ключа.
        byte[][] w = new byte[b * r][];
        for (int i = 0; i < w.Length; i++)
            w[i] = new byte[4];

        // Логика расширения ключа:
        //
        // W_i = K_i, если i < N;
        //       W_i-N xor SubWord(RotWord(W_i-1)) xor rcon_i/N,
        //           если i >= N и i % N == 0;
        //       W_i-N xor SubWord(W_i-1)
        //           если i >= N, N > 6, и i % N == 4;
        //       W_i-N xor W_i-1, иначе.

        for (int i = 0; i < w.Length; i++)
        {
            if (i < n)
            {
                Array.Copy(key, 4 * i, w[i], 0, 4);
            }
            else if (i % n == 0)
            {
                w[i] = Xor(
                    w[i - n],
                    Xor(
                        SubWord(RotWord(w[i - 1])),
                        _parameters.Rcon()[i / n - 1]
                    )
                );
            }
            else if (n < 6 && i % n == 4)
            {
                w[i] = Xor(w[i - n], SubWord(w[i - 1]));
            }
            else
            {
                w[i] = Xor(w[i - n], w[i - 1]);
            }
        }

        // Собираем раундовые ключи, хранящиеся в столбцах.
        byte[][] roundKeys = new byte[r][];
        for (int round = 0; round < roundKeys.Length; round++)
            roundKeys[round] = new byte[blockSize.Bytes()];

        for (int round = 0; round < roundKeys.Length; round++)
        {
            for (int column = 0; column < b; column++)
            {
                Array.Copy(
                    /* src */ w[round * b + column], 0,
                    /* dst */ roundKeys[round], column * 4,
                    /* len */ 4);
            }
        }

        return roundKeys;
    }

    private byte[] RotWord(byte[] word) 
        => new byte[] { word[1], word[2], word[3], word[0] };

    private byte[] SubWord(byte[] word) => new byte[]
    {
        _parameters.SBox().Lookup(word[0]),
        _parameters.SBox().Lookup(word[1]),
        _parameters.SBox().Lookup(word[2]),
        _parameters.SBox().Lookup(word[3]),
    };

    private static byte[] Xor(byte[] a, byte[] b)
    {
        byte[] result = new byte[4];
        for (int i = 0; i < result.Length; i++)
            result[i] = (byte)(a[i] ^ b[i]);
        return result;
    }
}
