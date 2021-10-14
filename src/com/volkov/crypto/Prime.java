package com.volkov.crypto;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class Prime {
    private static int[] LEAST;

    private static void init() {
        if (LEAST == null) LEAST = eratosthenes(2000);
    }

    /**
     * Генерация первых простых чисел < n (решето Эратосфена)
     * @param n - предел поиска
     * @return Целочисленный массив с найденными числами
     */
    private static int[] eratosthenes(int n) {
        boolean[] num = new boolean[n];
        for (int i = 0; i < n; i++) num[i] = true;
        int primes = n - 2;

        for (int i = 2; i * i < n; i++) {
            if (num[i]) {
                for (int j = i * i; j < n; j += i) {
                    if (num[j]) {
                        num[j] = false;
                        primes--;
                    }
                }
            }
        }

        int index = 0;
        int[] p = new int[primes];
        for (int i = 2; i < n; i++) {
            if (num[i]) {
                p[index] = i;
                index++;
            }
        }

        return p;
    }

    /**
     * Генерация случайного числа-кандидата в простые разрядности length
     * @param length - требуемая разрядность
     * @return Нечётное случайное число длины length (старшие биты - нули)
     */
    static BigInteger generate(int length) {
        SecureRandom random = new SecureRandom();
        BigInteger result;
        boolean divTest;

        // Число генерируется повторно, если не проходит тест делимости на малые простые
        do {
            divTest = false;

            result = new BigInteger(length, random);
            // Гарантируем длину
            result = result.setBit(length - 1);
            // Гарантируем нечётность
            result = result.setBit(0);

            for (int l : LEAST) {
                if (result.mod(BigInteger.valueOf((long) l)).compareTo(BigInteger.ZERO) == 0) {
                    divTest = true;
                    break;
                }
            }

        } while (divTest);

        return result;
    }

    /**
     * Тест Рабина-Миллера
     * @param num    - проверяемое число
     * @param rounds - число раундов
     * @return Простое или нет
     */
    static boolean millerRabin(BigInteger num, int rounds) {
        SecureRandom random = new SecureRandom();

        // Представим num в виде 2^r * d + 1, где d нечётно
        BigInteger div = num.subtract(BigInteger.ONE);
        int r = 0;
        while (div.mod(BigInteger.TWO).compareTo(BigInteger.ZERO) == 0) {
            div = div.divide(BigInteger.TWO);
            r++;
        }

        BigInteger d = num.subtract(BigInteger.ONE).divide(BigInteger.ONE.shiftLeft(r));
        BigInteger FOUR = BigInteger.valueOf(4L);

        witness_loop:
        for (int i = 0; i < rounds; i++) {
            // Выбрать случайное a в диапазоне [2, num - 2]
            BigInteger a = new BigInteger(num.bitLength(), random).subtract(FOUR).add(BigInteger.TWO);
            // x = a^d mod num
            BigInteger x = a.modPow(d, num);

            if (x.equals(BigInteger.ONE) || (x.compareTo(num.subtract(BigInteger.ONE))) == 0) continue;

            for (int j = 0; j < r - 1; j++) {
                // x = x^2 mod num
                x = x.modPow(BigInteger.TWO, num);
                if (x.compareTo(num.subtract(BigInteger.ONE)) == 0) continue witness_loop;
            }

            return false;
        }
        return true;
    }

    /**
     * Генерация простого числа заданной длины
     * @param bitLength - количество разрядов
     * @param rounds    - число раундов теста
     * @param threadNum - число потоков, используемых для генерации
     * @return Вероятно простое число заданной длины
     * @throws InterruptedException
     * @throws ExecutionException
     */
    public static BigInteger getPrime(int bitLength, int rounds, int threadNum) throws InterruptedException, ExecutionException {
        ExecutorService pool = Executors.newFixedThreadPool(threadNum);
        ArrayList<Future<BigInteger>> futures = new ArrayList<>();
        init();

        Expression prime = (l, r) -> {
            BigInteger num = Prime.generate(l);
            while (!millerRabin(num, r)) num = Prime.generate(l);
            return num;
        };

        for (int i = 0; i < threadNum; i++) futures.add(pool.submit(new Generator(prime, bitLength, rounds)));

        while (true) {
            for (Future<BigInteger> future : futures) {
                if (future.isDone()) {
                    BigInteger result = future.get();
                    pool.shutdownNow();
                    return result;
                }
            }
        }
    }

    /**
     * Генерация безопасного простого числа заданной длины
     * @param bitLength - количество разрядов
     * @param rounds - число раундов теста
     * @param threadNum - число потоков, используемых для генерации
     * @return Безопасное простое N, где N = 2q + 1, q - простое
     * @throws InterruptedException
     * @throws ExecutionException
     */
    public static BigInteger getSafePrime(int bitLength, int rounds, int threadNum) throws InterruptedException, ExecutionException {
        ExecutorService pool = Executors.newFixedThreadPool(threadNum);
        ArrayList<Future<BigInteger>> futures = new ArrayList<>();
        init();

        Expression safe = (l, r) -> {
            BigInteger num;
            boolean condition = false;
            do {
                num = Prime.generate(l);
                while (!millerRabin(num, r)) num = Prime.generate(l);
                // num = 2q + 1 -> q = (num - 1) / 2
                BigInteger q = num.subtract(BigInteger.ONE).shiftRight(1);
                condition = millerRabin(q, r);
            } while (!condition);
            return num;
        };

        for (int i = 0; i < threadNum; i++) futures.add(pool.submit(new Generator(safe, bitLength, rounds)));

        while (true) {
            for (Future<BigInteger> future : futures) {
                if (future.isDone()) {
                    BigInteger result = future.get();
                    pool.shutdownNow();
                    return result;
                }
            }
        }
    }
}

interface Expression {
    BigInteger generate(int bitLength, int rounds);
}