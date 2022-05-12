package de.androidcrypto.ntagapp;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.text.HtmlCompat;

import android.content.Intent;
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
import android.text.Html;
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
import java.util.Arrays;

public class MainActivity extends AppCompatActivity implements NfcAdapter.ReaderCallback {

    // this code is based on an stackoverflow.com answer:
    // https://stackoverflow.com/questions/64920307/how-to-write-ndef-records-to-nfc-tag
    // author: user Andrew, answered Nov 19, 2020 at 23:13


    TextView ndefMessage;
    Button readNdefMessage, writeNdefMessage, writeCiphertext, decryptCiphertext;
    String ndefMessageString;

    TextView ciphertextFound;
    TextView salt, nonce, ciphertext; // data shown as hex string
    TextView plaintext; // data shown as string
    byte[] saltBytes = new byte[0], nonceBytes = new byte[0], ciphertextBytes = new byte[0]; // real data
    byte[] plaintextBytes = new byte[0];
    EditText passphraseDecryption;

    Intent writeNdefMessageIntent, writeCiphertextIntent;

    private NfcAdapter mNfcAdapter;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        ndefMessage = findViewById(R.id.tvNdefMessage);
        readNdefMessage = findViewById(R.id.btnReadSector);
        writeNdefMessage = findViewById(R.id.btnWriteNdefMessage);
        writeNdefMessageIntent = new Intent(MainActivity.this, WriteTag.class);
        writeCiphertext = findViewById(R.id.btnWriteCiphertext);
        writeCiphertextIntent = new Intent(MainActivity.this, WriteCiphertext.class);

        ciphertextFound = findViewById(R.id.tvNdefCiphertextFound);
        salt = findViewById(R.id.tvNdefSalt);
        nonce = findViewById(R.id.tvNdefNonce);
        ciphertext = findViewById(R.id.tvNdefCiphertext);
        plaintext = findViewById(R.id.tvPlaintextDecrypted);
        decryptCiphertext = findViewById(R.id.btnDecryptCiphertext);
        passphraseDecryption = findViewById(R.id.etPassphraseDecryption);

        mNfcAdapter = NfcAdapter.getDefaultAdapter(this);
        //ciphertextFound.setText(HtmlCompat.fromHtml("<font color='#fb1100'>Your Title</font>", HtmlCompat.FROM_HTML_MODE_LEGACY);
/*
        readNdefMessage.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String timeNow = ZonedDateTime
                        .now(ZoneId.systemDefault())
                        .format(DateTimeFormatter.ofPattern("uuuu.MM.dd HH.mm.ss"));
                ndefMessage.setText(ndefMessageString + "\n" + timeNow);
            }
        });*/

        writeNdefMessage.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startActivity(writeNdefMessageIntent);
            }
        });

        writeCiphertext.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startActivity(writeCiphertextIntent);
            }
        });

        decryptCiphertext.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (checkCiphertextIsPresent()) {
                    int passphraseLength = 0;
                    if (passphraseDecryption != null) {
                        passphraseLength = passphraseDecryption.length();
                    }
                    // get the passphrase as char[]
                    char[] passphraseChar = new char[passphraseLength];
                    passphraseDecryption.getText().getChars(0, passphraseLength, passphraseChar, 0);
                    if (passphraseLength < 1) {
                        Toast.makeText(getApplicationContext(),
                                "Enter a longer passphrase",
                                Toast.LENGTH_SHORT).show();
                        return;
                    }
                    plaintextBytes = CryptoManager.aes256GcmPbkdf2Sha256Decryption2(saltBytes, nonceBytes, ciphertextBytes, passphraseChar);
                    if (plaintextBytes.length > 0) {
                        plaintext.setText(new String(plaintextBytes, StandardCharsets.UTF_8));
                    } else {
                        plaintext.setText("Error on decryption (wrong passphrase ???), try again");
                    }
                }
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
            // the option NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK is NOT set
            // to get the data of the tag afer reading
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
        // Read and or write to Tag here to the appropriate Tag Technology type class
        // in this example the card should be an Ndef Technology Type

        // clear the datafields
        clearEncryptionData();

        Ndef mNdef = Ndef.get(tag);

        if (mNdef == null) {
            runOnUiThread(() -> {
                Toast.makeText(getApplicationContext(),
                        "mNdef is null",
                        Toast.LENGTH_SHORT).show();
            });
        }

        // Check that it is an Ndef capable card
        if (mNdef != null) {

            // If we want to read
            // As we did not turn on the NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK
            // We can get the cached Ndef message the system read for us.

            NdefMessage mNdefMessage = mNdef.getCachedNdefMessage();
            ndefMessageString = mNdefMessage.toString();

            // Make a Sound
            try {
                Uri notification = RingtoneManager.getDefaultUri(RingtoneManager.TYPE_NOTIFICATION);
                Ringtone r = RingtoneManager.getRingtone(getApplicationContext(),
                        notification);
                r.play();
            } catch (Exception e) {
                // Some error playing sound
            }
            NdefRecord[] record = mNdefMessage.getRecords();
            String ndefContent = "";
            int ndefRecordsCount = record.length;
            ndefContent = "nr of records: " + ndefRecordsCount + "\n";
            // Success if got to here
            runOnUiThread(() -> {
                Toast.makeText(getApplicationContext(),
                        "Read from NFC success, number of records: " + ndefRecordsCount,
                        Toast.LENGTH_SHORT).show();
            });

            if (ndefRecordsCount > 0) {
                for (int i = 0; i < ndefRecordsCount; i++) {
                    short ndefInf = record[i].getTnf();
                    byte[] ndefType = record[i].getType();
                    byte[] ndefPayload = record[i].getPayload();
                    // check for encrypted content in an External NDEF message
                    short ndefInf4 = (short) 4;
                    if (Short.compare(ndefInf, ndefInf4) == 0) {
                        // this is a record type 4
                        byte[] saltDefinition = "de.androidcrypto.aes256gcmpbkdf2:salt".getBytes(StandardCharsets.UTF_8);
                        byte[] nonceDefinition = "de.androidcrypto.aes256gcmpbkdf2:nonce".getBytes(StandardCharsets.UTF_8);
                        byte[] ciphertextDefinition = "de.androidcrypto.aes256gcmpbkdf2:ciphertext".getBytes(StandardCharsets.UTF_8);
                        // checking for salt
                        if (Arrays.equals(ndefType, saltDefinition)) {
                            // salt definition found
                            saltBytes = Arrays.copyOf(ndefPayload, ndefPayload.length);
                        }
                        if (Arrays.equals(ndefType, nonceDefinition)) {
                            // nonce definition found
                            nonceBytes = Arrays.copyOf(ndefPayload, ndefPayload.length);
                        }
                        if (Arrays.equals(ndefType, ciphertextDefinition)) {
                            // ciphertext definition found
                            ciphertextBytes = Arrays.copyOf(ndefPayload, ndefPayload.length);
                        }
                    }

                    ndefContent = ndefContent + "rec " + i + " inf: " + ndefInf +
                            " type: " + bytesToHex(ndefType) +
                            " payload: " + bytesToHex(ndefPayload) +
                            " \n" + new String(ndefPayload) + " \n";
                    String finalNdefContent = ndefContent;
                    runOnUiThread(() -> {
                        ndefMessage.setText(finalNdefContent);
                    });
                    if (checkCiphertextIsPresent()) {
                        runOnUiThread(() -> {
                            salt.setText(bytesToHex(saltBytes));
                        });
                        runOnUiThread(() -> {
                            nonce.setText(bytesToHex(nonceBytes));
                        });
                        runOnUiThread(() -> {
                            ciphertext.setText(bytesToHex(ciphertextBytes));
                        });
                        runOnUiThread(() -> {
                            ciphertextFound.setVisibility(View.VISIBLE);
                        });
                        runOnUiThread(() -> {
                            passphraseDecryption.setVisibility(View.VISIBLE);
                        });
                        runOnUiThread(() -> {
                            decryptCiphertext.setVisibility(View.VISIBLE);
                        });
                    }
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
        plaintextBytes = new byte[0];
        runOnUiThread(() -> {
            salt.setText("");
        });
        runOnUiThread(() -> {
            nonce.setText("");
        });
        runOnUiThread(() -> {
            ciphertext.setText("");
        });
        runOnUiThread(() -> {
            plaintext.setText("");
        });
        // make the ciphertext found notification invisible until a complete dataset is found
        runOnUiThread(() -> {
            ciphertextFound.setVisibility(View.GONE);
        });
        runOnUiThread(() -> {
            passphraseDecryption.setVisibility(View.GONE);
        });
        // make the decryption button invisible until a complete dataset is found
        runOnUiThread(() -> {
            decryptCiphertext.setVisibility(View.GONE);
        });
        //salt.setText("");
        //nonce.setText("");
        //ciphertext.setText("");
        //plaintext.setText("");
    }

    public static String bytesToHex(byte[] bytes) {
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