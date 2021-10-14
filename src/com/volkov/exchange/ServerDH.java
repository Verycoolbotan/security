package com.volkov.exchange;

import com.volkov.crypto.Prime;

import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.util.concurrent.ExecutionException;

public class ServerDH {
    public static void main(String[] args) throws InterruptedException, ExecutionException {
        // Генерация случайного простого числа a
        BigInteger b = Prime.getPrime(50, 5, 4);

        try (ServerSocket server = new ServerSocket(8030)) {
            System.out.println("Ожидание клиента...");
            while (true) {
                Socket client = server.accept();
                System.out.println("Соединение установлено, порт " + client.getPort());

                try (DataOutputStream out = new DataOutputStream(client.getOutputStream());
                     DataInputStream in = new DataInputStream(client.getInputStream());
                     BufferedReader reader = new BufferedReader(new InputStreamReader(System.in))) {

                    BigInteger g = BigInteger.valueOf(in.readLong());
                    BigInteger p = BigInteger.valueOf(in.readLong());
                    BigInteger A = BigInteger.valueOf(in.readLong());

                    BigInteger B = g.modPow(b, p);
                    BigInteger K = A.modPow(b, p);
                    System.out.println("Получен ключ: " + String.format("%032X", K));

                    out.writeLong(B.longValue());
                    out.flush();

                    while (true) {
                        byte[] buffer = new byte[in.readInt()];
                        in.read(buffer);
                        System.out.println("Сообщение клиента: " + String.format("%032X", new BigInteger(1, buffer)));
                        String request = XOR.decode(buffer, K);
                        System.out.println("Расшифрованное сообщение клиента: " + request);

                        System.out.println("Ответ клиенту:");
                        String response = reader.readLine();
                        out.writeInt(response.getBytes().length);
                        out.write(XOR.encode(response, K));
                        out.flush();
                    }

                } catch (SocketException e) {
                    e.printStackTrace();
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
