package de.androidcrypto.ntagapp;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.security.keystore.KeyProtection;
import android.util.Base64;
import android.util.Log;

import androidx.annotation.RequiresApi;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Objects;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class CryptoManager {

    final String APP_TAG = "CryptoManager";
    private static final int PBKDF2_ITERATIONS = 10000;

    private static final String TRANSFORMATION_GCM = "AES/GCM/NoPadding";


    // https://www.techiedelight.com/concatenate-byte-arrays-in-java/
    public static byte[] concat(byte[]... arrays) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        if (arrays != null) {
            Arrays.stream(arrays).filter(Objects::nonNull)
                    .forEach(array -> out.write(array, 0, array.length));
        }
        return out.toByteArray();
    }

    // generated ciphertext is 32 byte salt 12 byte iv xx byte ciphertext
    public static byte[] aes256GcmPbkdf2Sha256Encryption(byte[] plaintext, char[] passphrase) {
        byte[] ciphertext = new byte[0];
        // generate 32 byte random salt
        SecureRandom secureRandom = new SecureRandom();
        byte[] salt = new byte[32];
        secureRandom.nextBytes(salt);
        SecretKeyFactory secretKeyFactory = null;
        try {
            secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec keySpec = new PBEKeySpec(passphrase, salt, PBKDF2_ITERATIONS, 32 * 8);
            byte[] secretKey = secretKeyFactory.generateSecret(keySpec).getEncoded();
            SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey, "AES");
            Cipher cipher = Cipher.getInstance(TRANSFORMATION_GCM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
            ciphertext = cipher.doFinal(plaintext);
            System.out.println("iv length: " + cipher.getIV().length);
            return concat(salt, cipher.getIV(), ciphertext);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
            return new byte[0];
        }
    }

    // return a byte[][], 0 = salt, 1 = nonce and 2 = ciphertext
    public static byte[][] aes256GcmPbkdf2Sha256Encryption2(byte[] plaintext, char[] passphrase) {
        byte[][] output = new byte[3][];
        byte[] ciphertext = new byte[0];
        // generate 32 byte random salt
        SecureRandom secureRandom = new SecureRandom();
        byte[] salt = new byte[32];
        secureRandom.nextBytes(salt);
        SecretKeyFactory secretKeyFactory = null;
        try {
            secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec keySpec = new PBEKeySpec(passphrase, salt, PBKDF2_ITERATIONS, 32 * 8);
            byte[] secretKey = secretKeyFactory.generateSecret(keySpec).getEncoded();
            SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey, "AES");
            Cipher cipher = Cipher.getInstance(TRANSFORMATION_GCM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
            ciphertext = cipher.doFinal(plaintext);
            System.out.println("nonce length: " + cipher.getIV().length);
            output[0] = salt;
            output[1] = cipher.getIV();
            output[2] = ciphertext;
            return output;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
            return new byte[0][];
        }
    }

    public static byte[] aes256GcmPbkdf2Sha256Decryption(byte[] completeCiphertext, char[] passphrase) {
        byte[] plaintext = new byte[0];
        // get 32 bytes salt, 12 bytes IV and xx bytes from the completeCiphertext
        byte[] salt = new byte[32];
        byte[] nonce = new byte[12];
        int ciphertextLength = completeCiphertext.length - 32 - 12;
        byte[] ciphertext = new byte[(ciphertextLength)];
        salt = java.util.Arrays.copyOfRange(completeCiphertext, 0, 32);
        nonce = java.util.Arrays.copyOfRange(completeCiphertext, 32, 44);
        ciphertext = java.util.Arrays.copyOfRange(completeCiphertext, 44, completeCiphertext.length);
        System.out.println("*** completeCiphertext length: " + completeCiphertext.length);
        System.out.println("complete:" + MainActivity.bytesToHex(completeCiphertext));
        System.out.println("salt l: " + salt.length + "d: " + MainActivity.bytesToHex(salt));
        System.out.println("iv l: " + nonce.length + "d: " + MainActivity.bytesToHex(nonce));
        System.out.println("cite l: " + ciphertext.length + "d: " + MainActivity.bytesToHex(ciphertext));

        SecretKeyFactory secretKeyFactory = null;
        try {
            secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec keySpec = new PBEKeySpec(passphrase, salt, PBKDF2_ITERATIONS, 32 * 8);
            byte[] secretKey = secretKeyFactory.generateSecret(keySpec).getEncoded();
            SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey, "AES");
            Cipher cipher = Cipher.getInstance(TRANSFORMATION_GCM);
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(16 * 8, nonce);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, gcmParameterSpec);
            return cipher.doFinal(ciphertext);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            return new byte[0];
        }
    }

    public static String base64Encoding(byte[] input) {
        return Base64.encodeToString(input, Base64.NO_WRAP);
    }

    public static byte[] base64Decoding(String input) {
        return Base64.decode(input, Base64.NO_WRAP);
    }





    public String encryptWithPassphrase(String plainData, char[] passphrase, String saltBase64) {
        // generate key with PBKDF2
        byte[] salt = base64Decoding(saltBase64);
        byte[] encrypted = new byte[0];
        try {
            byte[] secretKey = new byte[0];
            // api between 23 - 25 has no HmacSHA256 available, uses PBKDF class
            /*
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M &
                    Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
                byte[] passphraseByte = charArrayToByteArray(passphrase);
                secretKey = PBKDF.pbkdf2("HmacSHA256", passphraseByte, salt, PBKDF2_ITERATIONS, 32);
            }*/
            // api 26+ has HmacSHA256 available
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                SecretKeyFactory secretKeyFactory = null;
                secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                KeySpec keySpec = new PBEKeySpec(passphrase, salt, PBKDF2_ITERATIONS, 32 * 8);
                secretKey = secretKeyFactory.generateSecret(keySpec).getEncoded();
            }
            SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey, "AES");
            Cipher cipher = Cipher.getInstance(TRANSFORMATION_GCM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
            encrypted = cipher.doFinal(plainData.getBytes(StandardCharsets.UTF_8));
            return base64Encoding(cipher.getIV()) + ":" + base64Encoding(encrypted);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
            Log.e(APP_TAG, "encryptWithPassphrase error: " + e.toString());
            return "";
        }
    }

    public String decryptWithPassphrase(String cipherData, char[] passphrase, String saltBase64) {
        try {
            if (cipherData.equals("")) {
                Log.e(APP_TAG, "decryptWithPassphrase - cipherData is empty");
                return "";
            }
            byte[] decrypted = new byte[0];
            String[] parts = cipherData.split(":", 0);
            byte[] nonce = base64Decoding(parts[0]);
            byte[] ciphertextWithTag = base64Decoding(parts[1]);
            byte[] salt = base64Decoding(saltBase64);
            byte[] secretKey = new byte[0];
            // api between 23 - 25 has no HmacSHA256 available, uses PBKDF class
            /*
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M &
                    Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
                byte[] passphraseByte = charArrayToByteArray(passphrase);
                secretKey = PBKDF.pbkdf2("HmacSHA256", passphraseByte, salt, PBKDF2_ITERATIONS, 32);
            }*/
            // api 26+ has HmacSHA256 available
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                SecretKeyFactory secretKeyFactory = null;
                secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                KeySpec keySpec = new PBEKeySpec(passphrase, salt, PBKDF2_ITERATIONS, 32 * 8);
                secretKey = secretKeyFactory.generateSecret(keySpec).getEncoded();
            }
            SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey, "AES");
            Cipher cipher = Cipher.getInstance(TRANSFORMATION_GCM);
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(16 * 8, nonce);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, gcmParameterSpec);
            decrypted = cipher.doFinal(ciphertextWithTag);
            return new String(decrypted);
        } catch (GeneralSecurityException e) {
            Log.e(APP_TAG, "decryptWithPassphrase error: " + e.toString());
            return "";
        }
    }

    public String encryptWithCryptoObject(String plainData, Cipher cipher) {
        byte[] encrypted = new byte[0];
        try {
            encrypted = cipher.doFinal(plainData.getBytes(StandardCharsets.UTF_8));
            return base64Encoding(cipher.getIV()) + ":" + base64Encoding(encrypted);
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
            Log.e(APP_TAG, "encryptWithCryptoObject error: " + e.toString());
            return "";
        }
    }

    public String decryptWithCryptoObject(String cipherData, Cipher cipher, String keyName) {
        try {
            if (cipherData.equals("")) {
                Log.e(APP_TAG, "decryptWithCryptoObject - cipherData is empty");
                return "";
            }
            byte[] decrypted = new byte[0];
            String[] parts = cipherData.split(":", 0);
            byte[] nonce = base64Decoding(parts[0]);
            byte[] ciphertextWithTag = base64Decoding(parts[1]);
            // build cipher from scratch
            SecretKey secretKey = getSecretKey(keyName);
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(16 * 8, nonce);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);
            decrypted = cipher.doFinal(ciphertextWithTag);
            return new String(decrypted);
        } catch (BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException | InvalidKeyException e) {
            e.printStackTrace();
            Log.e(APP_TAG, "decryptWithCryptoObject error: " + e.toString());
            return "";
        }
    }

    public String encryptWithoutCryptoObject(String plainData, String keyName) {
        byte[] encrypted = new byte[0];
        try {
            Cipher cipher = getCipherForEncryption(keyName);
            encrypted = cipher.doFinal(plainData.getBytes(StandardCharsets.UTF_8));
            return base64Encoding(cipher.getIV()) + ":" + base64Encoding(encrypted);
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
            Log.e(APP_TAG, "encryptWithoutCryptoObject error: " + e.toString());
            return "";
        }
    }

    public String decryptWithoutCryptoObject(String cipherData, String keyName) {
        try {
            if (cipherData.equals("")) {
                Log.e(APP_TAG, "decryptWithoutCryptoObject - cipherData is empty");
                return "";
            }
            byte[] decrypted = new byte[0];
            String[] parts = cipherData.split(":", 0);
            byte[] nonce = base64Decoding(parts[0]);
            byte[] ciphertextWithTag = base64Decoding(parts[1]);
            // build cipher from scratch
            SecretKey secretKey = getSecretKey(keyName);
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(16 * 8, nonce);
            Cipher cipher = getCipherForEncryption(keyName);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);
            decrypted = cipher.doFinal(ciphertextWithTag);
            return new String(decrypted);
        } catch (BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException | InvalidKeyException e) {
            e.printStackTrace();
            Log.e(APP_TAG, "decryptWithoutCryptoObject error: " + e.toString());
            return "";
        }
    }

    public Cipher getCipherForEncryption(String keyName) {
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance(TRANSFORMATION_GCM);
            cipher.init(Cipher.ENCRYPT_MODE, getSecretKey(keyName));
            return cipher;
        } catch (KeyPermanentlyInvalidatedException e) {
            Log.e(APP_TAG, "KeyPermanentlyInvalidatedException: " + e.toString());
            return null;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
            e.printStackTrace();
            Log.e(APP_TAG, "getCipherForEncryption error: " + e.toString());
            return null;
        }
    }

    private SecretKey getSecretKey(String keyName) {
        KeyStore keyStore = null;
        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore");
            // Before the keystore can be accessed, it must be loaded.
            keyStore.load(null);
            return ((SecretKey) keyStore.getKey(keyName, null));
        } catch (KeyStoreException | UnrecoverableKeyException | NoSuchAlgorithmException | IOException | java.security.cert.CertificateException e) {
            e.printStackTrace();
            Log.e(APP_TAG, "getSecretkey error: " + e.toString());
            return null;
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.R)
    private void createSecretKeyApi30(String keyName) {
        generateSecretKey(new KeyGenParameterSpec.Builder(
                keyName,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                //.setInvalidatedByBiometricEnrollment(true)
                // Accept either a biometric credential or a device credential.
                // To accept only one type of credential, include only that type as the
                // second argument.
                // @RequiresApi(api = Build.VERSION_CODES.R)
                // timeout = 0 means auth per key use
                .setUserAuthenticationParameters(0,
                        KeyProperties.AUTH_BIOMETRIC_STRONG |
                                KeyProperties.AUTH_DEVICE_CREDENTIAL)
                .build());
    }// All exceptions unhandled

    //@RequiresApi(api = Build.VERSION_CODES.M)
    private void createSecretKeyApi2329(String keyName) {
        generateSecretKey(new KeyGenParameterSpec.Builder(
                keyName,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                //.setInvalidatedByBiometricEnrollment(true) // available on Api 24
                // Accept either a biometric credential or a device credential.
                // To accept only one type of credential, include only that type as the
                // second argument.
                // for SDK < 30 use .setUserAuthenticationValidityDurationSeconds(0)
                // see https://cs.android.com/android/platform/superproject/+/android-11.0.0_r3:frameworks/base/keystore/java/android/security/keystore/KeyGenParameterSpec.java;l=1236-1246;drc=a811787a9642e6a9e563f2b7dfb15b5ae27ebe98
                // parameter "0" defaults to AUTH_BIOMETRIC_STRONG | AUTH_DEVICE_CREDENTIAL
                // parameter "-1" default to AUTH_BIOMETRIC_STRONG
                .setUserAuthenticationValidityDurationSeconds(0)
                .build());
    }// All exceptions unhandled

    private void generateSecretKey(KeyGenParameterSpec keyGenParameterSpec) {
        KeyGenerator keyGenerator = null;
        try {
            keyGenerator = KeyGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            keyGenerator.init(keyGenParameterSpec);
            keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | NoSuchProviderException e) {
            Log.e(APP_TAG, "generateSecretkey error: " + e.toString());
            e.printStackTrace();
        }
    }

    public String generateAndStoreSecretKeyFromPassphrase(String keyName, char[] passphrase) {
        // generate 32 byte random salt for pbkdf2
        SecureRandom secureRandom = new SecureRandom();
        byte[] salt = new byte[32];
        secureRandom.nextBytes(salt);
        SecretKeyFactory secretKeyFactory = null;
        // api between 23 - 25
        /*
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M &
                Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            try {
                // uses 3rd party PBKDF function to get PBKDF2withHmacSHA256
                // PBKDF2withHmacSHA256	is available API 26+
                byte[] secretKey = new byte[0];
                byte[] passphraseByte = charArrayToByteArray(passphrase);
                secretKey = PBKDF.pbkdf2("HmacSHA256", passphraseByte, salt, PBKDF2_ITERATIONS, 32);
                SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey, "AES");
                KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
                keyStore.load(null);
                keyStore.setEntry(keyName,
                        new KeyStore.SecretKeyEntry(secretKeySpec),
                        new KeyProtection.Builder(KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                                .setRandomizedEncryptionRequired(true)
                                // for SDK < 30 use .setUserAuthenticationValidityDurationSeconds(0)
                                // see https://cs.android.com/android/platform/superproject/+/android-11.0.0_r3:frameworks/base/keystore/java/android/security/keystore/KeyGenParameterSpec.java;l=1236-1246;drc=a811787a9642e6a9e563f2b7dfb15b5ae27ebe98
                                // parameter "0" defaults to AUTH_BIOMETRIC_STRONG | AUTH_DEVICE_CREDENTIAL
                                // parameter "-1" default to AUTH_BIOMETRIC_STRONG
                                .setUserAuthenticationValidityDurationSeconds(0)
                                //.setUserAuthenticationParameters(0,KeyProperties.AUTH_BIOMETRIC_STRONG | KeyProperties.AUTH_DEVICE_CREDENTIAL)
                                .build());
                // now we do have the secretKey stored in the android keystroe
                return base64Encoding(salt);
            } catch (IOException | GeneralSecurityException e) {
                e.printStackTrace();
                Log.e(APP_TAG, "generateAndStoreSecretKeyFromPassphrase error: " + e.toString());
                return "";
            }
        }*/
        // api between 26-29
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O &
                Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
            try {
                secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                KeySpec keySpec = new PBEKeySpec(passphrase, salt, PBKDF2_ITERATIONS, 32 * 8);
                SecretKeySpec secretKeySpec = new SecretKeySpec(secretKeyFactory.generateSecret(keySpec).getEncoded(), "AES");
                KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
                keyStore.load(null);
                keyStore.setEntry(keyName,
                        new KeyStore.SecretKeyEntry(secretKeySpec),
                        new KeyProtection.Builder(KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                                .setRandomizedEncryptionRequired(true)
                                // for SDK < 30 use .setUserAuthenticationValidityDurationSeconds(0)
                                // see https://cs.android.com/android/platform/superproject/+/android-11.0.0_r3:frameworks/base/keystore/java/android/security/keystore/KeyGenParameterSpec.java;l=1236-1246;drc=a811787a9642e6a9e563f2b7dfb15b5ae27ebe98
                                // parameter "0" defaults to AUTH_BIOMETRIC_STRONG | AUTH_DEVICE_CREDENTIAL
                                // parameter "-1" default to AUTH_BIOMETRIC_STRONG
                                .setUserAuthenticationValidityDurationSeconds(0)
                                //.setUserAuthenticationParameters(0,KeyProperties.AUTH_BIOMETRIC_STRONG | KeyProperties.AUTH_DEVICE_CREDENTIAL)
                                .build());
                // now we do have the secretKey stored in the android keystroe
                return base64Encoding(salt);
            } catch (NoSuchAlgorithmException | InvalidKeySpecException | KeyStoreException | IOException | java.security.cert.CertificateException e) {
                e.printStackTrace();
                Log.e(APP_TAG, "generateAndStoreSecretKeyFromPassphrase error: " + e.toString());
                return "";
            }
        }
        // api > 30
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            try {
                secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                KeySpec keySpec = new PBEKeySpec(passphrase, salt, PBKDF2_ITERATIONS, 32 * 8);
                SecretKeySpec secretKeySpec = new SecretKeySpec(secretKeyFactory.generateSecret(keySpec).getEncoded(), "AES");
                KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
                keyStore.load(null);
                keyStore.setEntry(keyName,
                        new KeyStore.SecretKeyEntry(secretKeySpec),
                        new KeyProtection.Builder(KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                                .setRandomizedEncryptionRequired(true)
                                .setUserAuthenticationParameters(0,
                                        KeyProperties.AUTH_BIOMETRIC_STRONG |
                                                KeyProperties.AUTH_DEVICE_CREDENTIAL)
                                .build());
                // now we do have the secretKey stored in the android keystroe
                return base64Encoding(salt);
            } catch (NoSuchAlgorithmException | InvalidKeySpecException | KeyStoreException | IOException | java.security.cert.CertificateException e) {
                e.printStackTrace();
                Log.e(APP_TAG, "generateAndStoreSecretKeyFromPassphrase error: " + e.toString());
                return "";
            }
        }
        // as minimum SDK in build.gradle was set to 23 the version can't be below 23
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            Log.e(APP_TAG, "SDK in use is too old, minimum SDK is 23 = M");
        }
        return "";
    }

    public void listKeyNames() {
        /*
         * Load the Android KeyStore instance using the
         * "AndroidKeyStore" provider to list out what entries are
         * currently stored.
         */
        KeyStore ks = null;
        Log.d(APP_TAG, "list keyNames");
        try {
            ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            Enumeration<String> aliases = ks.aliases();
            // print the enumeration
            while (aliases.hasMoreElements()) {
                Log.d(APP_TAG, "keyNames: " + aliases.nextElement());
            }
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | java.security.cert.CertificateException e) {
            e.printStackTrace();
            Log.e(APP_TAG, "listKeyNames error: " + e.toString());
        }
    }

    public Enumeration<String> getkeyNames() {
        /*
         * Load the Android KeyStore instance using the
         * "AndroidKeyStore" provider to list out what entries are
         * currently stored.
         */
        KeyStore ks = null;
        try {
            ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            Enumeration<String> aliases = ks.aliases();
            return aliases;
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | java.security.cert.CertificateException e) {
            e.printStackTrace();
            Log.e(APP_TAG, "getKeyNames error: " + e.toString());
            return null;
        }
    }

    public KeyStore.SecretKeyEntry getSecretKeyEntry(String keyName) {
        KeyStore keyStore = null;
        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            return ((KeyStore.SecretKeyEntry) keyStore.getEntry(keyName, null));
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | UnrecoverableEntryException | java.security.cert.CertificateException e) {
            e.printStackTrace();
            Log.e(APP_TAG, "getSecretKeyEntry error: " + e.toString());
            return null;
        }
    }

    public void deleteSecretKeyEntry(String keyName) {
        KeyStore keyStore = null;
        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            keyStore.deleteEntry(keyName);
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | java.security.cert.CertificateException e) {
            Log.e(APP_TAG, "deleteSecretKey error: " + e.toString());
            e.printStackTrace();
        }
    }

    public String getRandomSaltString() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] bytes = new byte[8];
        secureRandom.nextBytes(bytes);
        return base64Encoding(bytes);
    }

    public boolean verifyPassphrase(char[] passphrase, String passphraseTeststring, String passphraseEncryptedTeststring, String saltBase64) {
        String decryptedtext = decryptWithPassphrase(passphraseEncryptedTeststring, passphrase, saltBase64);
        return decryptedtext.equals(passphraseTeststring);
    }



    // https://stackoverflow.com/a/9670279/8166854
    byte[] charArrayToByteArray(char[] chars) {
        CharBuffer charBuffer = CharBuffer.wrap(chars);
        ByteBuffer byteBuffer = Charset.forName("UTF-8").encode(charBuffer);
        byte[] bytes = Arrays.copyOfRange(byteBuffer.array(),
                byteBuffer.position(), byteBuffer.limit());
        Arrays.fill(byteBuffer.array(), (byte) 0); // clear sensitive data
        return bytes;
    }
    /*
    Solution is inspired from Swing recommendation to store passwords in char[].
    usage:
    char[] chars = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};
    byte[] bytes = toBytes(chars);
    // do something with chars/bytes
    Arrays.fill(chars, '\u0000'); // clear sensitive data
    Arrays.fill(bytes, (byte) 0); // clear sensitive data
     */
}


