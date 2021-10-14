package com.volkov.rsa;

import com.volkov.crypto.RSA;

import java.io.*;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.concurrent.ExecutionException;

public class ClientRSA {
    public static void main(String[] args) throws InterruptedException, ExecutionException {
        RSA keygen = new RSA(512, 5, 4);
        HashMap<String, BigInteger> PK = keygen.rsaPK();
        HashMap<String, BigInteger> SK = keygen.rsaSK();

        HashMap<String, BigInteger> serverPK = new HashMap<>();

        try (Socket client = new Socket(InetAddress.getLocalHost(), 8030);
             DataOutputStream out = new DataOutputStream(client.getOutputStream());
             DataInputStream in = new DataInputStream(client.getInputStream());
             BufferedReader reader = new BufferedReader(new InputStreamReader(System.in))) {

            // Отправка открытого ключа серверу
            byte[] buffer = PK.get("e").toByteArray();
            out.writeInt(buffer.length);
            out.write(buffer);
            buffer = PK.get("n").toByteArray();
            out.writeInt(buffer.length);
            out.write(buffer);

            // Получение открытого ключа сервера
            int length = in.readInt();
            buffer = new byte[length];
            in.read(buffer);
            serverPK.put("e", new BigInteger(buffer));
            length = in.readInt();
            buffer = new byte[length];
            in.read(buffer);
            serverPK.put("n", new BigInteger(buffer));

            System.out.println("Получен открытый ключ сервера");

            while(true) {
                System.out.println("Сообщение серверу: ");
                String msg = reader.readLine();
                byte[] from = RSA.rsaEncrypt(msg, serverPK).toByteArray();
                out.writeInt(from.length);
                out.write(from);
                out.flush();

                byte[] to = new byte[in.readInt()];
                in.read(to);
                BigInteger raw = new BigInteger(to);
                System.out.println("Ответ сервера:\n" + String.format("%032X", raw));
                msg = RSA.rsaDecrypt(raw, SK);
                System.out.println("Расшифрованный ответ сервера:\n" + msg);
            }

        } catch (UnknownHostException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
