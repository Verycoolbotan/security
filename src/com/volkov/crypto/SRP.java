package com.volkov.crypto;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;

public class SRP {
    private static MessageDigest digest = null;
    private static SecureRandom random = null;
    private static BigInteger k = BigInteger.valueOf(3L);

    public static void init() throws NoSuchAlgorithmException {
        if (digest == null) digest = MessageDigest.getInstance("SHA-256");
        if (random == null) random = new SecureRandom();
    }

    /**
     * Возвращает генератор по заданному модулю. Вычисление генератора аналогично нахождению первообразного
     * корня - требуется факторизация N-1. Если известно, что число - безопасное простое, то его разложение
     * уже известно.
     *
     * @param modulo - модуль
     * @param isSafe - является ли модуль безопасным простым
     * @return - генератор по модулю или -1, если искомое число не найдено
     */
    public static BigInteger generator(BigInteger modulo, boolean isSafe) {
        ArrayList<BigInteger> fact = new ArrayList<>();
        BigInteger phi = modulo.subtract(BigInteger.ONE);
        BigInteger n = phi;

        if (isSafe) {
            fact.add(BigInteger.TWO);
            fact.add(phi.shiftRight(1));
        } else {
            for (BigInteger i = BigInteger.TWO; i.pow(2).compareTo(n) < 0; i = i.add(BigInteger.ONE)) {
                if (n.remainder(i).compareTo(BigInteger.ZERO) == 0) {
                    fact.add(i);
                    while (n.remainder(i).compareTo(BigInteger.ZERO) == 0) {
                        n = n.divide(i);
                    }
                }
            }
            if (n.compareTo(BigInteger.ONE) > 0) fact.add(n);
        }

        for (BigInteger g = BigInteger.TWO; g.compareTo(modulo) <= 0; g = g.add(BigInteger.ONE)) {
            boolean condition = true;
            for (int i = 0; i < fact.size() && condition; ++i) {
                condition &= g.modPow(phi.divide(fact.get(i)), modulo).compareTo(BigInteger.ONE) != 0;
            }
            if (condition) return g;
        }

        return BigInteger.valueOf(-1L);
    }

    public static HashMap<String, BigInteger> genReg(HashMap<String, BigInteger> in, String password) {
        BigInteger s = new BigInteger(128, random);
        BigInteger x = new BigInteger(digest.digest(concat(s.toByteArray(), password.getBytes(StandardCharsets.UTF_16LE))));
        BigInteger v = in.get("g").modPow(x, in.get("N"));
        in.put("s", s);
        in.put("x", x);
        in.put("v", v);
        return in;
    }

    public static HashMap<String, BigInteger> serverExchangeInit(HashMap<String, BigInteger> in) {
        BigInteger b = new BigInteger(128, random);
        BigInteger N = in.get("N");
        BigInteger B = (k.multiply(in.get("v")).add(in.get("g").modPow(b, N))).remainder(N);
        in.put("B", B);
        in.put("b", b);
        return in;
    }

    public static HashMap<String, BigInteger> clientExchangeInit(HashMap<String, BigInteger> in, String password) {
        BigInteger x = new BigInteger(digest.digest(concat(in.get("s").toByteArray(), password.getBytes(StandardCharsets.UTF_16LE))));
        BigInteger a = new BigInteger(128, random);
        BigInteger A = in.get("g").modPow(a, in.get("N"));
        in.put("x", x);
        in.put("a", a);
        in.put("A", A);
        return in;
    }

    public static BigInteger getScrambler(BigInteger A, BigInteger B) {
        return new BigInteger(digest.digest(concat(A.toByteArray(), B.toByteArray())));
    }

    public static HashMap<String, BigInteger> clientSessionKey(HashMap<String, BigInteger> in) {
        BigInteger x = in.get("x");
        BigInteger B = in.get("B");
        BigInteger g = in.get("g");
        BigInteger N = in.get("N");
        BigInteger a = in.get("a");
        BigInteger u = in.get("u");
        BigInteger S = (B.subtract(k.multiply(g.modPow(x, N)))).modPow(a.add(u.multiply(x)), N);
        in.put("K", new BigInteger(digest.digest(S.toByteArray())));
        return in;
    }

    public static HashMap<String, BigInteger> serverSessionKey(HashMap<String, BigInteger> in) {
        BigInteger v = in.get("v");
        BigInteger b = in.get("b");
        BigInteger A = in.get("A");
        BigInteger N = in.get("N");
        BigInteger u = in.get("u");
        BigInteger S = (A.multiply(v.modPow(u, N))).modPow(b, N);
        in.put("K", new BigInteger(digest.digest(S.toByteArray())));
        return in;
    }

    public static BigInteger clientAck(HashMap<String, BigInteger> in, String username) {
        BigInteger N = in.get("N");
        BigInteger g = in.get("g");
        byte[] s = in.get("s").toByteArray();
        byte[] A = in.get("A").toByteArray();
        byte[] B = in.get("B").toByteArray();
        byte[] K = in.get("K").toByteArray();

        byte[] nHash = digest.digest(N.toByteArray());
        byte[] gHash = digest.digest(g.toByteArray());
        byte[] xor = new byte[nHash.length];
        for (int i = 0; i < nHash.length; i++) {
            xor[i] = (byte) (nHash[i] ^ gHash[i]);
        }
        byte[] iHash = digest.digest(username.getBytes(StandardCharsets.UTF_16LE));

        return new BigInteger(digest.digest(concat(concat(concat(xor, iHash), concat(s, A)), concat(B, K))));
    }

    public static BigInteger serverAck(BigInteger A, BigInteger M, BigInteger K) {
        return new BigInteger(digest.digest(concat(concat(A.toByteArray(), M.toByteArray()), K.toByteArray())));
    }

    /**
     * Конкатенация двух массивов
     *
     * @param a - первый массив
     * @param b - второй массив
     * @return - склеенный массив
     */
    private static byte[] concat(byte[] a, byte[] b) {
        byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }
}
