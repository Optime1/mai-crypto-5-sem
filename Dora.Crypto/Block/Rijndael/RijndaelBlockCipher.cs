namespace Dora.Crypto.Block.Rijndael;

/// <summary>
/// Блочный шифр Rijndael (AES).
/// </summary>
public sealed class RijndaelBlockCipher : IBlockCipher
{
    private readonly RijndaelParameters _parameters;
    private readonly RijndaelKeySchedule _keySchedule;
    private byte[][]? _roundKeys;

    public RijndaelBlockCipher(RijndaelParameters parameters)
    {
        _parameters = parameters ?? throw new ArgumentNullException(nameof(parameters));
        _keySchedule = new RijndaelKeySchedule(parameters);
    }

    public int BlockSize() => _parameters.BlockSize().Bytes();

    public void Init(byte[] key)
    {
        if (key == null) throw new ArgumentNullException(nameof(key));
        _roundKeys = _keySchedule.RoundKeys(key);
    }

    public byte[] Encrypt(byte[] plaintext)
    {
        if (_roundKeys == null)
            throw new InvalidOperationException("Cipher is not initialized");
        if (plaintext == null) throw new ArgumentNullException(nameof(plaintext));
        if (plaintext.Length != BlockSize())
            throw new ArgumentException("Invalid block size");

        byte[] state = (byte[])plaintext.Clone();
        state = AddRoundKey(state, _roundKeys[0]);

        for (int round = 1; round < _parameters.Rounds(); round++)
        {
            state = SubBytes(state);
            state = ShiftRows(state);
            state = MixColumns(state);
            state = AddRoundKey(state, _roundKeys[round]);
        }

        state = SubBytes(state);
        state = ShiftRows(state);
        state = AddRoundKey(state, _roundKeys[_parameters.Rounds()]);

        return state;
    }

    public byte[] Decrypt(byte[] ciphertext)
    {
        if (_roundKeys == null)
            throw new InvalidOperationException("Cipher is not initialized");
        if (ciphertext == null) throw new ArgumentNullException(nameof(ciphertext));
        if (ciphertext.Length != BlockSize())
            throw new ArgumentException("Invalid block size");

        byte[] state = (byte[])ciphertext.Clone();
        state = AddRoundKey(state, _roundKeys[_parameters.Rounds()]);

        for (int round = _parameters.Rounds() - 1; round >= 1; round--)
        {
            state = InvShiftRows(state);
            state = InvSubBytes(state);
            state = AddRoundKey(state, _roundKeys[round]);
            state = InvMixColumns(state);
        }

        state = InvShiftRows(state);
        state = InvSubBytes(state);
        state = AddRoundKey(state, _roundKeys[0]);

        return state;
    }

    private static byte[] AddRoundKey(byte[] state, byte[] roundKey)
    {
        byte[] result = new byte[state.Length];
        for (int i = 0; i < state.Length; i++)
            result[i] = (byte)(state[i] ^ roundKey[i]);
        return result;
    }

    #region SubBytes

    private byte[] SubBytes(byte[] state)
    {
        byte[] result = new byte[state.Length];
        for (int i = 0; i < state.Length; i++)
            result[i] = _parameters.SBox().Lookup(state[i]);
        return result;
    }

    private byte[] InvSubBytes(byte[] state)
    {
        byte[] result = new byte[state.Length];
        for (int i = 0; i < state.Length; i++)
            result[i] = _parameters.InverseSBox().Lookup(state[i]);
        return result;
    }

    #endregion

    #region ShiftRows

    private byte[] ShiftRows(byte[] state)
    {
        byte[] result = new byte[state.Length];
        int blockWords = _parameters.BlockSize().Words();

        for (int col = 0; col < blockWords; col++)
        {
            for (int row = 0; row < 4; row++)
            {
                int shiftCol = (col - row + blockWords) % blockWords;
                result[shiftCol * 4 + row] = state[col * 4 + row];
            }
        }

        return result;
    }

    private byte[] InvShiftRows(byte[] state)
    {
        byte[] result = new byte[state.Length];
        int blockWords = _parameters.BlockSize().Words();

        for (int col = 0; col < blockWords; col++)
        {
            for (int row = 0; row < 4; row++)
            {
                int shiftCol = (col + row) % blockWords;
                result[shiftCol * 4 + row] = state[col * 4 + row];
            }
        }

        return result;
    }

    #endregion

    #region MixColumns

    private byte[] MixColumns(byte[] state)
    {
        byte[] result = new byte[state.Length];
        var field = new GaloisField();

        // Матрица преобразования для MixColumns
        byte[] transformation = { 2, 3, 1, 1, 1, 2, 3, 1, 1, 1, 2, 3, 3, 1, 1, 2 };

        for (int col = 0; col < _parameters.BlockSize().Words(); col++)
        {
            for (int row = 0; row < 4; row++)
            {
                for (int k = 0; k < 4; k++)
                {
                    result[col * 4 + row] = field.Add(
                        field.MulModUnchecked(
                            state[col * 4 + k],
                            transformation[row * 4 + k],
                            _parameters.Modulus()
                        ),
                        result[col * 4 + row]
                    );
                }
            }
        }

        return result;
    }

    private byte[] InvMixColumns(byte[] state)
    {
        byte[] result = new byte[state.Length];
        var field = new GaloisField();

        // Обратная матрица преобразования в GF(2^8)
        byte[] transformation = { 0xe, 0xb, 0xd, 0x9, 0x9, 0xe, 0xb, 0xd, 0xd, 0x9, 0xe, 0xb, 0xb, 0xd, 0x9, 0xe };

        for (int col = 0; col < _parameters.BlockSize().Words(); col++)
        {
            for (int row = 0; row < 4; row++)
            {
                for (int k = 0; k < 4; k++)
                {
                    result[col * 4 + row] = field.Add(
                        field.MulModUnchecked(
                            state[col * 4 + k],
                            transformation[row * 4 + k],
                            _parameters.Modulus()
                        ),
                        result[col * 4 + row]
                    );
                }
            }
        }

        return result;
    }

    #endregion
}
