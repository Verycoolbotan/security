package com.volkov.rsa;

import com.volkov.crypto.RSA;

import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.util.HashMap;
import java.util.concurrent.ExecutionException;

public class ServerRSA {
    public static void main(String[] args) throws InterruptedException, ExecutionException {
        RSA keygen = new RSA(512, 5, 4);
        HashMap<String, BigInteger> PK = keygen.rsaPK();
        HashMap<String, BigInteger> SK = keygen.rsaSK();

        HashMap<String, BigInteger> clientPK = new HashMap<>();

        try (ServerSocket server = new ServerSocket(8030)) {
            System.out.println("Ожидание клиента...");
            while (true) {
                Socket client = server.accept();
                System.out.println("Соединение установлено, порт " + client.getPort());

                try (DataOutputStream out = new DataOutputStream(client.getOutputStream());
                     DataInputStream in = new DataInputStream(client.getInputStream());
                     BufferedReader reader = new BufferedReader(new InputStreamReader(System.in))) {

                    // Получение открытого ключа клиента
                    int length = in.readInt();
                    byte[] buffer = new byte[length];
                    in.read(buffer);
                    clientPK.put("e", new BigInteger(buffer));
                    length = in.readInt();
                    buffer = new byte[length];
                    in.read(buffer);
                    clientPK.put("n", new BigInteger(buffer));

                    System.out.println("Получен открытый ключ клиента");

                    // Отправка открытого ключа клиенту
                    buffer = PK.get("e").toByteArray();
                    out.writeInt(buffer.length);
                    out.write(buffer);
                    buffer = PK.get("n").toByteArray();
                    out.writeInt(buffer.length);
                    out.write(buffer);

                    while (true) {
                        byte[] from = new byte[in.readInt()];
                        in.read(from);
                        BigInteger raw = new BigInteger(from);
                        System.out.println("Сообщение клиента:\n" + String.format("%032X", raw));
                        String msg = RSA.rsaDecrypt(raw, SK);
                        System.out.println("Расшифрованное сообщение клиента:\n" + msg);

                        System.out.println("Сообщение клиенту: ");
                        msg = reader.readLine();
                        byte[] to = RSA.rsaEncrypt(msg, clientPK).toByteArray();
                        out.writeInt(to.length);
                        out.write(to);
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
