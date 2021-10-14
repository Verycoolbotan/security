package com.volkov.crypto;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.concurrent.ExecutionException;

public class RSA {
    private BigInteger n;
    private BigInteger e;
    private BigInteger d;

    public RSA(int bitLength, int rounds, int threadNum) throws InterruptedException, ExecutionException {
        BigInteger p = Prime.getPrime(bitLength, rounds, threadNum);
        BigInteger q = Prime.getPrime(bitLength, rounds, threadNum);

        SecureRandom random = new SecureRandom();

        n = p.multiply(q);
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        // e взаимно простое с phi, т.е. НОД(e, phi) = 1
        do {
            // Установка нулевого бита в 1 гарантирует нечётность
            e = new BigInteger(phi.bitLength() / 32 + 1, random).setBit(0);
        } while (e.gcd(phi).compareTo(BigInteger.ONE) != 0);

        d = e.modInverse(phi);
    }

    /**
     * @return Возвращает открытый ключ
     */
    public HashMap<String, BigInteger> rsaPK() {
        HashMap<String, BigInteger> PK = new HashMap<>();
        PK.put("e", e);
        PK.put("n", n);
        return PK;
    }

    /**
     * @return Возвращает закрытый ключ
     */
    public HashMap<String, BigInteger> rsaSK() {
        HashMap<String, BigInteger> SK = new HashMap<>();
        SK.put("d", d);
        SK.put("n", n);
        return SK;
    }

    public static BigInteger rsaEncrypt(String text, HashMap<String, BigInteger> PK) {
        BigInteger m = new BigInteger(text.getBytes(StandardCharsets.UTF_16LE));
        return m.modPow(PK.get("e"), PK.get("n"));
    }

    public static String rsaDecrypt(BigInteger text, HashMap<String, BigInteger> SK) {
        BigInteger m = text.modPow(SK.get("d"), SK.get("n"));
        return new String(m.toByteArray(), StandardCharsets.UTF_16LE);
    }
}
