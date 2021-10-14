package com.volkov.crypto;

import java.math.BigInteger;
import java.util.concurrent.Callable;

public class Generator implements Callable {
    private int bitLength;
    private int rounds;

    private Expression gen;

    public Generator(Expression gen, int bitLength, int rounds){
        this.gen = gen;
        this.bitLength = bitLength;
        this.rounds = rounds;
    }

    @Override
    public BigInteger call() {
        return gen.generate(bitLength, rounds);
    }
}
