package com.volkov.exchange;

import com.volkov.crypto.Prime;

import java.io.*;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.Random;
import java.util.concurrent.ExecutionException;

public class ClientDH {
    public static void main(String[] args) throws InterruptedException, ExecutionException {
        // Генерация случайного простого числа a
        BigInteger a = Prime.getPrime(50, 5, 4);

        // Генерация публичных данных
        Random random = new Random();
        BigInteger g = new BigInteger(50, random);
        BigInteger p = new BigInteger(50, random);
        BigInteger A = g.modPow(a, p);

        // Обмен данными
        try (Socket client = new Socket(InetAddress.getLocalHost(), 8030);
             DataOutputStream out = new DataOutputStream(client.getOutputStream());
             DataInputStream in = new DataInputStream(client.getInputStream());
             BufferedReader reader = new BufferedReader(new InputStreamReader(System.in))) {

            // Отправить публичные данные на сервер
            out.writeLong(g.longValue());
            out.writeLong(p.longValue());
            out.writeLong(A.longValue());
            out.flush();

            // Принять B и получтиь ключ
            BigInteger B = BigInteger.valueOf(in.readLong());
            BigInteger K = B.modPow(a, p);
            System.out.println("Получен ключ: " + String.format("%032X", K));

            while (true) {
                System.out.println("Сообщение серверу: ");
                String request = reader.readLine();
                out.writeInt(request.getBytes().length);
                out.write(XOR.encode(request, K));
                out.flush();

                byte[] buffer = new byte[in.readInt()];
                in.read(buffer);
                System.out.println("Ответ сервера:\n" + String.format("%032X", new BigInteger(1, buffer)));
                String response = XOR.decode(buffer, K);
                System.out.println("Расшифрованный ответ сервера:\n" + response);
            }

        } catch (UnknownHostException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
