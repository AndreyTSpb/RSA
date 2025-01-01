import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;

/**
 *
 * @author EnotPotaskun
 */
public class RSA {
    private static final String inputFile = "D:\\java\\GOST_28147\\input.txt"; // шифруемый файл
    private static final String outputFile = "D:\\java\\GOST_28147\\output.enc"; // зашифрованный файл
    private static final String decryptedFile = "D:\\java\\GOST_28147\\decrypt.txt"; // расшифрованный файл

    private BigInteger p; //случайное число p
    private BigInteger q; //случайное число q
    private final BigInteger n; //модуль p*q
    private BigInteger phi; //функция Эйлера φ
    private BigInteger e; //открытая экспонента
    private final BigInteger d; //закрытая экспонента
    private final int bitlength = 1024; //Длинна ключа 
    private Random r;

    public RSA() {
        r = new Random();
        p = BigInteger.probablePrime(bitlength, r);
        q = BigInteger.probablePrime(bitlength, r);
        n = p.multiply(q); //Вычисляем модуль — произведение наших p и q
        
        System.out.printf("P:%d \n", p);
        System.out.printf("Q:%d \n", q);
        System.out.printf("N:%d \n", n);

        phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE)); //Вычисляем функцию Эйлера: φ=(p-1)×(q-1)

        e = BigInteger.probablePrime(bitlength / 2, r); //Получаем открытую экспонент
        while (phi.gcd(e).compareTo(BigInteger.ONE) > 0 && e.compareTo(phi) < 0) {
            e = e.add(BigInteger.ONE);
        }

        d = e.modInverse(phi); // Устанавливаем d
    }

    public RSA(BigInteger e, BigInteger d, BigInteger n) {
        this.e = e;
        this.d = d;
        this.n = n;
    }

    public static void main(String[] args) throws IOException {
        RSA rsa = new RSA();
        
        // Чтение оригинального текста из файла
        byte[] plaintext = readFile(inputFile);
        //String initStrMsg = getTextFromFile(inputFile); //переменная с текстом из файла
        System.out.println("Original text: " + new String(plaintext));
        System.out.println("Original text in bytes: " + bytesToString(plaintext));
        
        // Шифрование
        byte[] encrypted = rsa.encrypt(plaintext, 256);
        System.out.println("Encrypted text in Bytes: " + encrypted.length);
        System.out.println("Encrypted text in Bytes: " + bytesToString(encrypted));
        
        // Запись зашифрованного текста в файл
        writeFile(outputFile, encrypted);
        System.out.println("Encrypted text written to: " + outputFile);
        
        // Чтение зашифрованного текста из файла 
        byte[] outpuText = readFile(outputFile);
        System.out.println("Encrypted text in bytes from file: " + bytesToString(outpuText));
        
        // Дешифрование
        byte[] decrypted = rsa.decrypt(outpuText, 256);
        System.out.println("Decrypting text in bytes: " + bytesToString(decrypted));
        System.out.println("Decrypted text: " + new String(decrypted));
        
        //Запись расшифрованного текста в фаил
        writeFile(decryptedFile, decrypted);
        System.out.println("Decrypted text written to: " + decryptedFile);
    }
    
    /**
     * Байтовый массив в строку
     * @param encrypted
     * @return 
     */
    private static String bytesToString(byte[] data)
    {
        String str = "";
        for (byte b : data) str += Byte.toString(b);
        return str;
    }

    /**
     * Чтение файла
     * @param filePath -путь и название файла
     * @return
     * @throws IOException 
     */
    private static byte[] readFile(String filePath) throws IOException {
        return new FileInputStream(filePath).readAllBytes();
    }

    /**
     * Запись в файл
     * @param filePath -путь и название файла
     * @param data - данные для записи
     * @throws IOException 
     */
    private static void writeFile(String filePath, byte[] data) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            fos.write(data);
        }
    }

    /**
     * Шифровка сообщния
     * @param text
     * @return 
     */
    public byte[] encrypt_byte(byte[] text) {
        return (new BigInteger(text)).modPow(e, n).toByteArray();
    }

    /**
     * Дешифровка сообщения
     * @param text
     * @return 
     */
    public byte[] decrypt_byte(byte[] text) {
        return (new BigInteger(text)).modPow(d, n).toByteArray();
    }
    
    /**
     * Шифровка сообщения блочными размерами
     * @param text
     * @param blockSize - 256
     * @return
     * @throws java.io.IOException
     */
    public byte[] encrypt(byte[] text, int blockSize) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        
        for (int i = 0; i < text.length; i += blockSize) {
            int length = Math.min(blockSize, text.length - i);
            byte[] block = Arrays.copyOfRange(text, i, i + length);
            byte[] encryptedBlock = encrypt_block(block);
            outputStream.write(encryptedBlock);
            System.out.println("Encrypted block: " + new String(block) + " --> " + Base64.getEncoder().encodeToString(encryptedBlock)); // Вывод зашифрованного блока
        }
        
        return outputStream.toByteArray();
    }
    
    private byte[] encrypt_block(byte[] block) {
        return (new BigInteger(1, block)).modPow(e, n).toByteArray();
    }

    /**
     * Дешифровка сообщения блочными размерами
     * @param text
     * @param blockSize
     * @return
     * @throws java.io.IOException
     */
    public byte[] decrypt(byte[] text, int blockSize) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        int blockCount = text.length / blockSize;

        for (int i = 0; i < blockCount; i++) {
            byte[] block = Arrays.copyOfRange(text, i * blockSize, (i + 1) * blockSize);
            byte[] decryptedBlock = decrypt_block(block);
            outputStream.write(decryptedBlock);
            System.out.println("Decrypted block: " + Base64.getEncoder().encodeToString(block) + " --> " + new String(decryptedBlock)); // Вывод расшифрованного блока
        }

        // Обработка остатка, если есть
        int remaining = text.length % blockSize;
        if (remaining > 0) {
            byte[] block = Arrays.copyOfRange(text, blockCount * blockSize, text.length);
            byte[] decryptedBlock = decrypt_block(block);
            outputStream.write(decryptedBlock);
            System.out.println("Decrypted remaining block: " + Base64.getEncoder().encodeToString(block) + " --> " + new String(decryptedBlock)); // Вывод остатка
        }

        return outputStream.toByteArray();
    }

    private byte[] decrypt_block(byte[] block) {
        return (new BigInteger(1, block)).modPow(d, n).toByteArray();
    }
}
