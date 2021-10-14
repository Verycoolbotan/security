package com.volkov.srp;

import com.volkov.crypto.SRP;

import java.io.*;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;

public class ClientSRP {
    private static final int NOT_FOUND = 0;
    private static final int LOG_IN = 1;
    private static String username;
    private static String password;
    private static HashMap<String, BigInteger> params = null;

    public static void main(String[] args) throws NoSuchAlgorithmException {
        SRP.init();

        try (Socket client = new Socket(InetAddress.getLocalHost(), 8030);
             DataOutputStream out = new DataOutputStream(client.getOutputStream());
             DataInputStream in = new DataInputStream(client.getInputStream());
             BufferedReader reader = new BufferedReader(new InputStreamReader(System.in))) {
            // Запросить данные для входа, отправить серверу username
            credentials(out, reader);
            // Принять ответ сервера
            switch (in.readInt()) {
                case NOT_FOUND:
                    System.out.println("Пользователь не найден; регистрация...");
                    register(out, in);
                    break;
                case LOG_IN:
                    logIn(out, in);
                    System.out.println(String.format("Ключ сессии: %X", params.get("K")));
                    break;
                default:
                    throw new ExchangeException("Ошибка сервера");
            }
        } catch (EOFException e) {
            System.out.println("Сервер разорвал соединение");
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ExchangeException e) {
            System.out.println(e.getMessage());
        }
    }

    private static void credentials(DataOutputStream out, BufferedReader reader) throws IOException {
        System.out.print("Username: ");
        username = reader.readLine();
        byte[] buffer = username.getBytes(StandardCharsets.UTF_16LE);
        System.out.print("Password: ");
        password = reader.readLine();
        out.writeInt(buffer.length);
        out.write(buffer);
    }

    private static void register(DataOutputStream out, DataInputStream in) throws IOException {
        params = new HashMap<>();
        params.put("N", new BigInteger(get(in)));
        params.put("g", new BigInteger(get(in)));
        // Сгенерировать соль с верификатором и отправить на сервер
        SRP.genReg(params, password);
        send(params.get("s"), out);
        send(params.get("v"), out);
    }

    private static void logIn(DataOutputStream out, DataInputStream in) throws IOException, ExchangeException {
        params = new HashMap<>();
        params.put("N", new BigInteger(get(in)));
        params.put("g", new BigInteger(get(in)));
        params.put("s", new BigInteger(get(in)));
        // Сгенерировать и отправить A
        SRP.clientExchangeInit(params, password);
        send(params.get("A"), out);
        BigInteger B = new BigInteger(get(in));
        // Разорвать соединение, если B = 0
        if (B.compareTo(BigInteger.ZERO) == 0) throw new ExchangeException("Illegal parameter");
        params.put("B", B);
        // Разорвать соединение, если u = 0
        BigInteger u = SRP.getScrambler(params.get("A"), B);
        if (u.compareTo(BigInteger.ZERO) == 0) throw new ExchangeException("Illegal hash");
        params.put("u", u);
        // Вычислить ключ
        SRP.clientSessionKey(params);

        // Фаза 2
        // Отправить подтверждение
        BigInteger M = SRP.clientAck(params, username);
        send(M, out);
        // Принять подтверждение сервера
        BigInteger R = SRP.serverAck(params.get("A"), M, params.get("K"));
        BigInteger serverR = new BigInteger(get(in));
        // Разорвать соединение, если R не равны
        if (R.compareTo(serverR) != 0) throw new ExchangeException("Ключи не совпадают");
    }

    private static void send(BigInteger i, DataOutputStream out) throws IOException {
        byte[] buffer = i.toByteArray();
        out.writeInt(buffer.length);
        out.write(buffer);
    }

    private static byte[] get(DataInputStream in) throws IOException {
        byte[] buffer = new byte[in.readInt()];
        in.read(buffer);
        return buffer;
    }


}
