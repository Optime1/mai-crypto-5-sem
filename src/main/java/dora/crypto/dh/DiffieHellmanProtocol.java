package dora.crypto.dh;

import dora.crypto.rsa.NumberTheory;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class DiffieHellmanProtocol {
    private final BigInteger p; // Модуль группы (простое число)
    private final BigInteger g; // Генератор группы
    private final BigInteger privateKey;
    private final BigInteger publicKey;

    // Стандартный генератор
    private static final SecureRandom random = new SecureRandom();

    /**
     * Конструктор участника. Генерирует приватную пару ключей на основе параметров группы.
     *
     * @param p Простой модуль.
     * @param g Генератор.
     */
    public DiffieHellmanProtocol(BigInteger p, BigInteger g) {
        this.p = p;
        this.g = g;

        // 1. Генерируем приватный ключ: случайное число < p
        // Обычно берут длину бит чуть меньше p, но для простоты возьмем p.bitLength() - 1
        this.privateKey = new BigInteger(p.bitLength() - 1, random);

        // 2. Вычисляем публичный ключ: A = g^a mod p
        this.publicKey = NumberTheory.modPow(g, privateKey, p);
    }

    public BigInteger getPublicKey() {
        return publicKey;
    }

    public BigInteger getP() {
        return p;
    }

    public BigInteger getG() {
        return g;
    }

    /**
     * Вычисляет общий секрет на основе публичного ключа собеседника.
     * Formula: S = (Public_Key_Other)^private_key mod p
     */
    public BigInteger computeSharedSecret(BigInteger otherPublicKey) {
        return NumberTheory.modPow(otherPublicKey, privateKey, p);
    }

    /**
     * Превращает общий секрет (BigInteger) в симметричный ключ (byte[]).
     * Использует SHA-256 для сжатия/расширения до 32 байт (256 бит).
     */
    public byte[] deriveSymmetricKey(BigInteger otherPublicKey) {
        BigInteger sharedSecret = computeSharedSecret(otherPublicKey);

        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            // toByteArray может добавить лишний нулевой байт знака, но для хеша это допустимо,
            // главное, чтобы у обоих участников байтовое представление было идентичным.
            return sha256.digest(sharedSecret.toByteArray());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }
}