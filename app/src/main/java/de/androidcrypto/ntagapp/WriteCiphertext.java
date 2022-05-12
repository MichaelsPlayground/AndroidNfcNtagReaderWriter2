package de.androidcrypto.ntagapp;

import androidx.appcompat.app.AppCompatActivity;

import android.media.Ringtone;
import android.media.RingtoneManager;
import android.net.Uri;
import android.nfc.FormatException;
import android.nfc.NdefMessage;
import android.nfc.NdefRecord;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.TagLostException;
import android.nfc.tech.Ndef;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

public class WriteCiphertext extends AppCompatActivity implements NfcAdapter.ReaderCallback {

    EditText plaintext, passphrase;
    Button encryptData;
    TextView salt, nonce, ciphertext; // data shown as hex string
    byte[] saltBytes = new byte[0], nonceBytes = new byte[0], ciphertextBytes = new byte[0]; // real data

    private NfcAdapter mNfcAdapter;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_write_ciphertext);

        plaintext = findViewById(R.id.etPlaintext);
        passphrase = findViewById(R.id.etPassphrase);
        encryptData = findViewById(R.id.btnEncryptData);
        salt = findViewById(R.id.tvSalt);
        nonce = findViewById(R.id.tvNonce);
        ciphertext = findViewById(R.id.tvCiphertext);

        mNfcAdapter = NfcAdapter.getDefaultAdapter(this);

        encryptData.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                clearEncryptionData();
                int passphraseLength = 0;
                if (passphrase != null) {
                    passphraseLength = passphrase.length();
                }
                // get the passphrase as char[]
                char[] passphraseChar = new char[passphraseLength];
                passphrase.getText().getChars(0, passphraseLength, passphraseChar, 0);
                if (passphraseLength < 1) {
                    Toast.makeText(getApplicationContext(),
                            "Enter a longer passphrase",
                            Toast.LENGTH_SHORT).show();
                    return;
                }
                int plaintextLength = plaintext.getText().length();
                if (plaintextLength < 1) {
                    Toast.makeText(getApplicationContext(),
                            "Enter a longer plaintext",
                            Toast.LENGTH_SHORT).show();
                    return;
                }
                if (plaintextLength > 50) {
                    Toast.makeText(getApplicationContext(),
                            "Enter a shorter plaintext, maximum is 50 characters",
                            Toast.LENGTH_SHORT).show();
                    return;
                }
                byte[][] result = CryptoManager.aes256GcmPbkdf2Sha256Encryption2(String.valueOf(plaintext.getText()).getBytes(StandardCharsets.UTF_8), passphraseChar);
                salt.setText(bytesToHex(result[0]));
                nonce.setText(bytesToHex(result[1]));
                ciphertext.setText(bytesToHex(result[2]));
                // real values for usage with NTAG writing
                saltBytes = result[0];
                nonceBytes = result[1];
                ciphertextBytes = result[2];
                System.out.println("*** decrypted: " + new String(CryptoManager.aes256GcmPbkdf2Sha256Decryption2(result[0], result[1], result[2], passphraseChar), StandardCharsets.UTF_8));
            }
        });
    }

    @Override
    protected void onResume() {
        super.onResume();

        if (mNfcAdapter != null) {
            Bundle options = new Bundle();
            // Work around for some broken Nfc firmware implementations that poll the card too fast
            options.putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 250);

            // Enable ReaderMode for all types of card and disable platform sounds
            mNfcAdapter.enableReaderMode(this,
                    this,
                    NfcAdapter.FLAG_READER_NFC_A |
                            NfcAdapter.FLAG_READER_NFC_B |
                            NfcAdapter.FLAG_READER_NFC_F |
                            NfcAdapter.FLAG_READER_NFC_V |
                            NfcAdapter.FLAG_READER_NFC_BARCODE |
                            NfcAdapter.FLAG_READER_NO_PLATFORM_SOUNDS,
                    options);
        }

    }

    @Override
    protected void onPause() {
        super.onPause();
        if (mNfcAdapter != null)
            mNfcAdapter.disableReaderMode(this);
    }

    // This method is run in another thread when a card is discovered
    // !!!! This method cannot cannot direct interact with the UI Thread
    // Use `runOnUiThread` method to change the UI from this method
    @Override
    public void onTagDiscovered(Tag tag) {
        // first check that ciphertext is present, if not give a message and return
        if (checkCiphertextIsPresent() == false) {
            runOnUiThread(() -> {
                Toast.makeText(getApplicationContext(),
                        "There is no ciphertext available. Enter the fields and press ENCRYPT",
                        //"Enter data and encrypt",
                        Toast.LENGTH_SHORT).show();
            });
        } else {
            // the thread only runs when ciphertext is present

            // Read and or write to Tag here to the appropriate Tag Technology type class
            // in this example the card should be an Ndef Technology Type
            Ndef mNdef = Ndef.get(tag);

            // Check that it is an Ndef capable card
            if (mNdef != null) {

                // If we want to read
                // As we did not turn on the NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK
                // We can get the cached Ndef message the system read for us.

                //NdefMessage mNdefMessage = mNdef.getCachedNdefMessage();
                //ndefMessageString = mNdefMessage.toString();

                // Or if we want to write a Ndef message
                // Create a Ndef text record
                String headerString = "Encryption was done with AES-256 GCM PBKDF2 on ";
                String timeNow = ZonedDateTime
                        .now(ZoneId.systemDefault())
                        .format(DateTimeFormatter.ofPattern("uuuu.MM.dd HH.mm.ss"));
                NdefRecord ndefRecord1Text = NdefRecord.createTextRecord("en", headerString +
                        timeNow);

                NdefRecord ndefRecord2ExternalSalt = NdefRecord.createExternal("de.androidcrypto.aes256gcmpbkdf2", "salt", saltBytes);
                NdefRecord ndefRecord3ExternalNonce = NdefRecord.createExternal("de.androidcrypto.aes256gcmpbkdf2", "nonce", nonceBytes);
                NdefRecord ndefRecord4ExternalCiphertext = NdefRecord.createExternal("de.androidcrypto.aes256gcmpbkdf2", "ciphertext", ciphertextBytes);
                // Create a Ndef URI record
                String uriString = "http://androidcrypto.bplaced.net";
                NdefRecord ndefRecord5Uri = NdefRecord.createUri(uriString);
                // Create a Ndef Android application record
                String packageName = "de.androidcrypto.ntagapp";
                NdefRecord ndefRecord6Aar = NdefRecord.createApplicationRecord(packageName);

                // Add to a NdefMessage
                //NdefMessage mMsg = new NdefMessage(ndefRecord1Text); // this gives exact 1 message with 1 record
                NdefMessage mMsg = new NdefMessage(ndefRecord1Text, ndefRecord2ExternalSalt, ndefRecord3ExternalNonce, ndefRecord4ExternalCiphertext, ndefRecord5Uri, ndefRecord6Aar); // gives 1 message with 6 records
                // Catch errors

                try {
                    mNdef.connect();
                    mNdef.writeNdefMessage(mMsg);
                    // Success if got to here
                    runOnUiThread(() -> {
                        Toast.makeText(getApplicationContext(),
                                "Write to NFC Success",
                                Toast.LENGTH_SHORT).show();
                    });
                    // Make a Sound
                    try {
                        Uri notification = RingtoneManager.getDefaultUri(RingtoneManager.TYPE_NOTIFICATION);
                        Ringtone r = RingtoneManager.getRingtone(getApplicationContext(),
                                notification);
                        r.play();
                    } catch (Exception e) {
                        // Some error playing sound
                    }
                } catch (FormatException e) {
                    runOnUiThread(() -> {
                        Toast.makeText(getApplicationContext(),
                                "FormatException: " + e,
                                Toast.LENGTH_SHORT).show();
                    });
                    // if the NDEF Message to write is malformed
                } catch (TagLostException e) {
                    runOnUiThread(() -> {
                        Toast.makeText(getApplicationContext(),
                                "TagLostException: " + e,
                                Toast.LENGTH_SHORT).show();
                    });
                    // Tag went out of range before operations were complete
                } catch (IOException e) {
                    // if there is an I/O failure, or the operation is cancelled
                    runOnUiThread(() -> {
                        Toast.makeText(getApplicationContext(),
                                "IOException: " + e,
                                Toast.LENGTH_SHORT).show();
                    });
                } finally {
                    // Be nice and try and close the tag to
                    // Disable I/O operations to the tag from this TagTechnology object, and release resources.
                    try {
                        mNdef.close();
                    } catch (IOException e) {
                        // if there is an I/O failure, or the operation is cancelled
                        runOnUiThread(() -> {
                            Toast.makeText(getApplicationContext(),
                                    "IOException: " + e,
                                    Toast.LENGTH_SHORT).show();
                        });
                    }
                }

                // Make a Sound
                try {
                    Uri notification = RingtoneManager.getDefaultUri(RingtoneManager.TYPE_NOTIFICATION);
                    Ringtone r = RingtoneManager.getRingtone(getApplicationContext(),
                            notification);
                    r.play();
                } catch (Exception e) {
                    runOnUiThread(() -> {
                        Toast.makeText(getApplicationContext(),
                                "Exception: " + e,
                                Toast.LENGTH_SHORT).show();
                    });
                    // Some error playing sound
                }
            }
        }
    }

    @Override
    public void onPointerCaptureChanged(boolean hasCapture) {
        super.onPointerCaptureChanged(hasCapture);
    }

    // checks that a complete set of data of ciphertext
    // is available
    private boolean checkCiphertextIsPresent() {
        boolean saltAvailable = false;
        boolean nonceAvailable = false;
        boolean ciphertextAvailable = false;
        boolean ciphertextIsPresent = false;
        if (saltBytes.length > 31) saltAvailable = true;
        if (nonceBytes.length > 11) nonceAvailable = true;
        if (ciphertextBytes.length > 16) ciphertextAvailable = true;
        if (saltAvailable && nonceAvailable && ciphertextAvailable) ciphertextIsPresent = true;
        return ciphertextIsPresent;
    }

    private void clearEncryptionData() {
        saltBytes = new byte[0];
        nonceBytes = new byte[0];
        ciphertextBytes = new byte[0];
        salt.setText("");
        nonce.setText("");
        ciphertext.setText("");
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuffer result = new StringBuffer();
        for (byte b : bytes) result.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
        return result.toString();
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }
}