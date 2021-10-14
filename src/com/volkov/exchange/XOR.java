package com.volkov.exchange;

import java.math.BigInteger;

public class XOR {
    static byte[] encode(String pText, BigInteger pKey) {
        byte[] txt = pText.getBytes();
        byte[] key = pKey.toByteArray();
        byte[] res = new byte[txt.length];

        for (int i = 0; i < txt.length; i++) {
            res[i] = (byte) (txt[i] ^ key[i % key.length]);
        }

        return res;
    }

    static String decode(byte[] pText, BigInteger pKey) {
        byte[] res = new byte[pText.length];
        byte[] key = pKey.toByteArray();

        for (int i = 0; i < res.length; i++) {
            res[i] = (byte) (pText[i] ^ key[i % key.length]);
        }

        return new String(res);
    }
}
