package de.androidcrypto.ntagapp;

import java.io.UnsupportedEncodingException;

public final class HexDumpUtil {
    // source: https://gist.github.com/jen20/906db194bd97c14d91df by jen20
    public static String formatHexDump(byte[] array, int offset, int length) {
        final int width = 16;
        StringBuilder builder = new StringBuilder();
        for (int rowOffset = offset; rowOffset < offset + length; rowOffset += width) {
            builder.append(String.format("%06d:  ", rowOffset));

            for (int index = 0; index < width; index++) {
                if (rowOffset + index < array.length) {
                    builder.append(String.format("%02x ", array[rowOffset + index]));
                } else {
                    builder.append("   ");
                }
            }
            if (rowOffset < array.length) {
                int asciiWidth = Math.min(width, array.length - rowOffset);
                builder.append("  |  ");
                try {
                    //builder.append(new String(array, rowOffset, asciiWidth, "UTF-8").replaceAll("\r\n", " ").replaceAll("\n", " "));

                    // this is a recommendation by another user
                    builder.append(new String(array, rowOffset, asciiWidth, "US-ASCII").replaceAll("[^\\x20-\\x7E]", "."));
                } catch (UnsupportedEncodingException ignored) {
                    //If UTF-8 isn't available as an encoding then what can we do?!
                }
            }

            builder.append(String.format("%n"));
        }

        return builder.toString();
    }
}
