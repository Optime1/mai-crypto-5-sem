namespace Dora.Crypto.Block.Rijndael;

/// <summary>
/// Константы раундов (Rcon) для Rijndael.
/// </summary>
public sealed class RijndaelRcon
{
    /// <summary>
    /// Константа раунда <c>rcon_i</c> для раунда <c>i</c> расширения ключа — 32-битное слово:
    /// <c>rcon_i = [rc_i, 0, 0, 0]</c>.
    /// </summary>
    private readonly byte[][] _rcon;

    /// <summary>
    /// Инициализирует константы раундов Rijndael.
    /// </summary>
    /// <param name="modulus">Неприводимый модуль в GF(2^8).</param>
    /// <param name="keyWords">Длина ключа в 32-битных словах.</param>
    /// <param name="blockWords">Длина блока в 32-битных словах.</param>
    /// <param name="rounds">Количество раундов.</param>
    internal RijndaelRcon(short modulus, int keyWords, int blockWords, int rounds)
    {
        _rcon = new byte[(int)Math.Ceiling((double)(blockWords * (rounds + 1)) / keyWords)][];
        for (int i = 0; i < _rcon.Length; i++)
            _rcon[i] = new byte[4];

        var field = new GaloisField();
        Init(field, modulus);
    }

    public byte[][] Value => _rcon;

    private void Init(GaloisField field, short modulus)
    {
        _rcon[0][0] = 0b1;

        for (int i = 1; i < _rcon.Length; i++)
        {
            _rcon[i][0] = field.MulModUnchecked(_rcon[i - 1][0], 0b10, modulus);
        }
    }
}
