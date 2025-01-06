import java.io.DataInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class RSA
{
    private BigInteger P;
    private BigInteger Q;
    private BigInteger N;
    private BigInteger PHI;
    private BigInteger e;
    private BigInteger d;
    private int bitlength = 2048; // Увеличьте размер до 2048 бит для большего сообщения
    private Random R;

    public static final String ANSI_RESET = "\u001B[0m"; 
    public static final String ANSI_YELLOW = "\u001B[33m";
    public static final String ANSI_RED = "\u001B[31m";
    public static final String ANSI_GREEN = "\u001B[32m";
       

    public RSA()
    {
        R = new Random();
        P = BigInteger.probablePrime(bitlength / 2, R);
        Q = BigInteger.probablePrime(bitlength / 2, R);
        N = P.multiply(Q);
        PHI = P.subtract(BigInteger.ONE).multiply(Q.subtract(BigInteger.ONE));
        e = BigInteger.probablePrime(bitlength / 4, R);
        while (PHI.gcd(e).compareTo(BigInteger.ONE) > 0 && e.compareTo(PHI) < 0)
        {
            e.add(BigInteger.ONE);
        }
        d = e.modInverse(PHI);
    }

    public RSA(BigInteger e, BigInteger d, BigInteger N)
    {
        this.e = e;
        this.d = d;
        this.N = N;
    }

    public static void main(String[] arguments) throws IOException
    {
        System.out.println(ANSI_YELLOW + "########----------- Start RSA -------------#########" + ANSI_RESET);
        
        RSA rsa = new RSA();

        String inputString = "The term RSA is an acronym for Rivest-Shamir-Adleman who brought out the algorithm in 1977. RSA is an asymmetric cryptographic algorithm which is used for encryption purposes so that only the required sources should know the text and no third party should be allowed to decrypt the text as it is encrypted. RSA works on the fact that it is very hard to factorize large numbers (order of 100+ digits). The term “Asymmetric” signifies that there are two keys public (known to all) and private (only at the receiver).";

        System.out.println(ANSI_RED + "Encrypting the message: " + ANSI_RESET + inputString);
        
        // Разделяем сообщение на части
        List<byte[]> messageParts = splitMessage(inputString.getBytes(), rsa.bitlength / 8);
        
        // Шифруем каждую часть
        List<byte[]> encryptedParts = new ArrayList<>();
        for (byte[] part : messageParts) {
            encryptedParts.add(rsa.encryptMessage(part));
        }

        // Теперь дешифруем каждую часть
        StringBuilder decryptedMessage = new StringBuilder();
        for (byte[] encryptedPart : encryptedParts) {
            byte[] decryptedPart = rsa.decryptMessage(encryptedPart);
            decryptedMessage.append(new String(decryptedPart));
        }

        System.out.println("---------------------------------------------------");
        System.out.println(ANSI_GREEN + "Decrypted message is: "+ ANSI_RESET + decryptedMessage.toString());
        System.out.println(ANSI_YELLOW + "#########----------- END RSA -------------#########" + ANSI_RESET);
    }

    private static List<byte[]> splitMessage(byte[] message, int partSize) {
        List<byte[]> parts = new ArrayList<>();
        for (int i = 0; i < message.length; i += partSize) {
            int length = Math.min(partSize, message.length - i);
            byte[] part = new byte[length];
            System.arraycopy(message, i, part, 0, length);
            parts.add(part);
        }
        return parts;
    }

    // Encrypting the message
    public byte[] encryptMessage(byte[] message)
    {
        return (new BigInteger(1, message)).modPow(e, N).toByteArray();
    }

    // Decrypting the message
    public byte[] decryptMessage(byte[] message)
    {
        return (new BigInteger(1, message)).modPow(d, N).toByteArray();
    }
}
