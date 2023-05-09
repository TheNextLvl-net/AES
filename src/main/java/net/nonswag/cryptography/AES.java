package net.nonswag.cryptography;

import core.annotation.FieldsAreNonnullByDefault;
import core.annotation.MethodsReturnNonnullByDefault;
import core.annotation.ParametersAreNonnullByDefault;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

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
@Getter
@RequiredArgsConstructor
@FieldsAreNonnullByDefault
@ParametersAreNonnullByDefault
@MethodsReturnNonnullByDefault
public class AES {
    private final Key key;

    /**
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
     * decode any given string that was encoded using the same key
     * @param value the string you want to decode
     * @return the encoded string
     * @throws NoSuchAlgorithmException thrown when the aes cypher was not found
     * @throws InvalidKeyException thrown when the input was encoded with another key
     */
    public String decode(String value) throws NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        return decode(value.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * decode any given bytes that where encoded using the same key
     * @param value the bytes you want to decode
     * @return the encoded string
     * @throws NoSuchAlgorithmException thrown when the aes cypher was not found
     * @throws InvalidKeyException thrown when the input was encoded with another key
     */
    public String decode(byte[] value) throws NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher aes = getCypher();
        aes.init(Cipher.DECRYPT_MODE, key);
        return new String(aes.doFinal(Base64.getDecoder().decode(value)));
    }

    /**
     * encode any given string
     * @param value the string you want to encode
     * @return the decoded string
     * @throws NoSuchAlgorithmException thrown when the aes cypher was not found
     */
    public String encode(String value) throws NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        return encode(value.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * decode any given bytes
     * @param value the bytes you want to encode
     * @return the decoded string
     * @throws NoSuchAlgorithmException thrown when the aes cypher was not found
     */
    public String encode(byte[] value) throws NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher aes = getCypher();
        aes.init(Cipher.ENCRYPT_MODE, key);
        return Base64.getEncoder().encodeToString(aes.doFinal(value));
    }

    /**
     * @return the aes cypher
     * @throws NoSuchAlgorithmException thrown when the aes cypher was not found
     */
    private Cipher getCypher() throws NoSuchAlgorithmException {
        try {
            return Cipher.getInstance("AES");
        } catch (NoSuchPaddingException e) {
            throw new IllegalStateException(e);
        }
    }
}
