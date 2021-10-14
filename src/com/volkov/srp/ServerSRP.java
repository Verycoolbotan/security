package com.volkov.srp;

import com.volkov.crypto.Prime;
import com.volkov.crypto.SRP;

import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.concurrent.ExecutionException;

public class ServerSRP {
    private static final int NOT_FOUND = 0;
    private static final int LOG_IN = 1;
    private static HashMap<String, BigInteger> params = null;
    private static HashMap<String, User> users = null;

    public static void main(String[] args) throws InterruptedException, ExecutionException, NoSuchAlgorithmException {
        init();
        SRP.init();

        try (ServerSocket server = new ServerSocket(8030)) {
            System.out.println("Ожидание клиента...");
            Socket client = server.accept();
            System.out.println("Соединение установлено, порт " + client.getPort());

            try (DataOutputStream out = new DataOutputStream(client.getOutputStream());
                 DataInputStream in = new DataInputStream(client.getInputStream())) {
                String username = new String(get(in), StandardCharsets.UTF_16LE);
                if (users.get(username) != null) {
                    out.writeInt(LOG_IN);
                    logIn(username, out, in);
                } else {
                    out.writeInt(NOT_FOUND);
                    register(username, out, in);
                    serialize();
                    System.out.println("Пользователь зарегестрирован");
                }
            } catch (SocketException e) {
                e.printStackTrace();
            }

            System.out.println(String.format("Ключ сессии: %X", params.get("K")));

        } catch (IOException | ExchangeException e) {
            e.printStackTrace();
        }
    }

    private static void init() {
        params = new HashMap<>();
        try (FileInputStream fileIn = new FileInputStream("users.dat");
             ObjectInputStream in = new ObjectInputStream(fileIn)) {
            if (users == null) users = (HashMap<String, User>) in.readObject();
        } catch (IOException e) {
            users = new HashMap<>();
        } catch (ClassNotFoundException e) {
            System.out.println("FATAL ERROR");
            e.printStackTrace();
        }
    }

    private static void register(String username, DataOutputStream out, DataInputStream in)
            throws IOException, InterruptedException, ExecutionException {
        BigInteger N = Prime.getSafePrime(128, 5, 4);
        BigInteger g = SRP.generator(N, true);
        // Отправить параметры клиенту
        send(N, out);
        send(g, out);
        // Принять соль и верификатор
        BigInteger s = new BigInteger(get(in));
        BigInteger v = new BigInteger(get(in));
        // Записать данные в таблицу
        users.put(username, new User(N, g, s, v));
    }

    private static void logIn(String username, DataOutputStream out, DataInputStream in) throws IOException, ExchangeException {
        User user = users.get(username);
        send(user.N, out);
        send(user.g, out);
        send(user.salt, out);
        BigInteger A = new BigInteger(get(in));
        // Разорвать соединение, если A = 0
        if (A.compareTo(BigInteger.ZERO) == 0) throw new ExchangeException("Illegal parameter");

        params.put("N", user.N);
        params.put("g", user.g);
        params.put("s", user.salt);
        params.put("v", user.verifier);
        params.put("A", A);
        SRP.serverExchangeInit(params);

        // Отправить клиенту B
        send(params.get("B"), out);
        // Разорвать соединение, если u = 0
        BigInteger u = SRP.getScrambler(A, params.get("B"));
        if (u.compareTo(BigInteger.ZERO) == 0) throw new ExchangeException("Illegal hash");
        params.put("u", u);
        // Вычислить ключ
        SRP.serverSessionKey(params);

        // Фаза 2
        // Принять подтверждение клиента
        BigInteger M = SRP.clientAck(params, username);
        BigInteger clientM = new BigInteger(get(in));
        // Разорвать соединение, если ключи не совпадают
        if (M.compareTo(clientM) != 0) throw new ExchangeException("Ключи не совпадают");
        // Отправить подтверждение клиенту
        send(SRP.serverAck(A, M, params.get("K")), out);
    }

    private static void serialize() {
        try (FileOutputStream fileOut = new FileOutputStream("users.dat");
             ObjectOutputStream out = new ObjectOutputStream(fileOut)) {
            out.writeObject(users);
        } catch (IOException e) {
            e.printStackTrace();
        }
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

class User implements Serializable{
    public BigInteger N;
    public BigInteger g;
    public BigInteger salt;
    public BigInteger verifier;

    public User(BigInteger N, BigInteger g, BigInteger s, BigInteger v) {
        this.N = N;
        this.g = g;
        this.salt = s;
        this.verifier = v;
    }
}