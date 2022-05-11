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
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import java.io.IOException;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

public class WriteTag extends AppCompatActivity implements NfcAdapter.ReaderCallback{

    EditText dataToWriteOnTag;
    TextView readContent;
    String ndefMessageString;

    private NfcAdapter mNfcAdapter;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_write_tag);

        dataToWriteOnTag = findViewById(R.id.etWriteContent);
        readContent = findViewById(R.id.tvReadContent);

        mNfcAdapter = NfcAdapter.getDefaultAdapter(this);
    }

    @Override
    protected void onResume() {
        super.onResume();

        if(mNfcAdapter!= null) {
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
        if(mNfcAdapter!= null)
            mNfcAdapter.disableReaderMode(this);
    }

    // This method is run in another thread when a card is discovered
    // !!!! This method cannot cannot direct interact with the UI Thread
    // Use `runOnUiThread` method to change the UI from this method
    @Override
    public void onTagDiscovered(Tag tag) {
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
            String timeNow = ZonedDateTime
                    .now(ZoneId.systemDefault())
                    .format(DateTimeFormatter.ofPattern("uuuu.MM.dd HH.mm.ss"));
            NdefRecord ndefRecord1Text = NdefRecord.createTextRecord("en", String.valueOf(dataToWriteOnTag.getText()) +
                    timeNow);
            // Create a Ndef Android application record
            String packageName = "de.androidcrypto.ntagapp";
            NdefRecord ndefRecord2Aar = NdefRecord.createApplicationRecord(packageName);
            // Create a Ndef URI record
            String uriString = "http://androidcrypto.bplaced.net";
            NdefRecord ndefRecord3Uri = NdefRecord.createUri(uriString);
            // Add to a NdefMessage
            //NdefMessage mMsg = new NdefMessage(ndefRecord1Text); // this gives exact 1 message with 1 record
            NdefMessage mMsg = new NdefMessage(ndefRecord1Text, ndefRecord3Uri, ndefRecord2Aar); // gives 1 message with 3 records
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

    @Override
    public void onPointerCaptureChanged(boolean hasCapture) {
        super.onPointerCaptureChanged(hasCapture);
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