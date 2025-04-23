package net.thenextlvl.crypto.aes;

import org.jspecify.annotations.NullMarked;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * An Advanced Encryption Standard (short: AES) implementation
 */
@NullMarked
public class AES {
    private final Key key;

    /**
     * Based on the key size, AES supports three variants:
     * <ul>
     *     <li>AES-128 (128 bits)</li>
     *     <li>AES-192 (192 bits)</li>
     *     <li>AES-256 (256 bits)</li>
     * </ul>
     *
     * Read more about
     * <a href="https://www.baeldung.com/java-secure-aes-key">Generating a Secure AES Key</a>
     *
     * @param secret the secret key that should be used for de- and encoding
     */
    public AES(byte[] secret) {
        this(new SecretKeySpec(secret, "AES"));
    }

    /**
     * @param secretKey the secret key that should be used for de- and encoding
     */
    public AES(String secretKey) {
        this(secretKey.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Constructs a new AES instance with the provided cryptographic key.
     *
     * @param key the cryptographic key that should be used for encryption and decryption
     */
    public AES(Key key) {
        this.key = key;
    }

    /**
     * Decrypt any given string that was encrypted using the same key
     *
     * @param value the string you want to decrypt
     * @return the encrypted string
     * @throws NoSuchAlgorithmException thrown when the aes cipher was not found
     * @throws InvalidKeyException thrown when the input was encrypted with another key
     */
    public String decrypt(String value) throws NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        return decrypt(value.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Decrypt any given bytes that where encrypted using the same key
     *
     * @param value the bytes you want to decrypt
     * @return the encrypted string
     * @throws NoSuchAlgorithmException thrown when the aes cipher was not found
     * @throws InvalidKeyException thrown when the input was encrypted with another key
     */
    public String decrypt(byte[] value) throws NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher aes = getCipher();
        aes.init(Cipher.DECRYPT_MODE, key);
        return new String(aes.doFinal(Base64.getDecoder().decode(value)));
    }

    /**
     * Encrypt any given string
     *
     * @param value the string you want to encrypt
     * @return the decrypted string
     * @throws NoSuchAlgorithmException thrown when the aes cipher was not found
     */
    public String encrypt(String value) throws NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        return encrypt(value.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Decrypt any given bytes
     *
     * @param value the bytes you want to encrypt
     * @return the decrypted string
     * @throws NoSuchAlgorithmException thrown when the aes cipher was not found
     */
    public String encrypt(byte[] value) throws NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher aes = getCipher();
        aes.init(Cipher.ENCRYPT_MODE, key);
        return Base64.getEncoder().encodeToString(aes.doFinal(value));
    }

    /**
     * Retrieves the cryptographic key used by this instance of AES.
     *
     * @return the cryptographic key
     */
    public Key getKey() {
        return key;
    }

    private Cipher getCipher() throws NoSuchAlgorithmException {
        try {
            return Cipher.getInstance("AES");
        } catch (NoSuchPaddingException e) {
            throw new IllegalStateException(e);
        }
    }
}
