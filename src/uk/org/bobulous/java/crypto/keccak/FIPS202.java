/*
 * Copyright © 2017 Bobulous <http://www.bobulous.org.uk/>.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/.
 */
package uk.org.bobulous.java.crypto.keccak;

import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;
import java.util.function.UnaryOperator;

/**
 * The SHA-3 family of hash functions standardised by NIST in FIPS PUB 202.
 * <p>
 * The National Institute of Standards and Technology define these functions in
 * the document
 * <a href="http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf">FIPS PUB
 * 202</a> "SHA-3 Standard: Permutation-Based Hash and Extendable-Output
 * Functions". The functions are entirely powered by the the
 * <a href="http://keccak.noekeon.org/">
 * <span style="font-variant: small-caps">Keccak</span>
 * sponge function family</a> created by <cite>Guido Bertoni, Joan Daemen,
 * Michaël Peeters, and Gilles Van Assche</cite>.</p>
 */
public final class FIPS202 {

	private FIPS202() {
		// This is a utility class which is never intended to be instantiated.
	}

	/**
	 * The SHA3 hash functions defined by NIST in
	 * <a href="http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf">FIPS
	 * PUB 202</a> "SHA-3 Standard: Permutation-Based Hash and Extendable-Output
	 * Functions". Each of the SHA3 hash functions is defined with a specific,
	 * fixed output length. All of the SHA3 hash functions use a domain suffix
	 * of "01" to separate them from other applications of the
	 * <span style="font-variant: small-caps">Keccak</span> sponge function.
	 *
	 * @see ExtendableOutputFunction
	 * @see KeccakSponge
	 */
	public enum HashFunction implements UnaryOperator<byte[]> {
		/**
		 * The SHA3-224 hash function, with a security level of 112 bits, and a
		 * fixed output length of 224 bits.
		 */
		SHA3_224((short) 1152, (short) 448, "01", 224),
		/**
		 * The SHA3-256 hash function, with a security level of 128 bits, and a
		 * fixed output length of 256 bits.
		 */
		SHA3_256((short) 1088, (short) 512, "01", 256),
		/**
		 * The SHA3-384 hash function, with a security level of 192 bits, and a
		 * fixed output length of 384 bits.
		 */
		SHA3_384((short) 832, (short) 768, "01", 384),
		/**
		 * The SHA3-512 hash function, with a security level of 256 bits, and a
		 * fixed output length of 512 bits.
		 */
		SHA3_512((short) 576, (short) 1024, "01", 512);

		private final short bitrate;
		private final short capacity;
		private final String suffixBits;
		private final int outputLengthInBits;

		/**
		 * The underlying {@code KeccakSponge} object which powers this SHA3
		 * hash function.
		 */
		private KeccakSponge spongeFunction;

		private HashFunction(short r, short c, String d, int l) {
			bitrate = r;
			capacity = c;
			suffixBits = d;
			outputLengthInBits = l;
		}

		private KeccakSponge getSpongeFunction() {
			if (spongeFunction == null) {
				initialiseSpongeFunction();
			}
			return spongeFunction;
		}

		/*
		 * Lazily initialises the sponge function object, so long as no other
		 * thread has already done so.
		 */
		private synchronized void initialiseSpongeFunction() {
			if (spongeFunction != null) {
				// Another thread beat us to it; no need to initialise again.
				return;
			}
			spongeFunction = new KeccakSponge(bitrate, capacity,
					suffixBits, outputLengthInBits);
		}

		/**
		 * Applies this hash function to the given message. Every bit contained
		 * by the byte array will be considered part of the message. The
		 * returned byte array will contain all of the bits of the calculated
		 * hash.
		 * <p>
		 * The given message byte array will not be modified by this method.
		 * However, to avoid problems, the message byte array should not be
		 * accessible to any other threads while it is being used to calculate
		 * the hash. If the message comes from a shared resource then take a
		 * copy and pass the copy to this method.</p>
		 * <p>
		 * Every bit of the returned byte array will be part of the hash
		 * result.</p>
		 *
		 * @param message a byte array which exactly represents the message.
		 * @return a byte array which contains the calculated hash. Must not be
		 * {@code null}.
		 */
		@Override
		public byte[] apply(byte[] message) {
			Objects.requireNonNull(message);
			return getSpongeFunction().apply(message);
		}

		/**
		 * Applies this hash function to the specified number of bits from the
		 * given message byte array. Only the first {@code messageLengthInBits}
		 * bits found within the {@code message} array will be considered part
		 * of the message to be hashed, and any subsequent bits will be ignored.
		 * <p>
		 * Bits are taken first from the message byte with the lowest index, and
		 * within each byte the least-significant bits are taken first. For
		 * example, if the given message byte array contains two bytes, and the
		 * specified message length is ten bits, then all of the bits from the
		 * byte at array index zero will be included, and from the second byte
		 * only the bits indices zero (the least significant bit) one will be
		 * included.</p>
		 * <p>
		 * The given message byte array will not be modified by this method.
		 * However, to avoid problems, the message byte array should not be
		 * accessible to any other threads while it is being used to calculate
		 * the hash. If the message comes from a shared resource then take a
		 * copy and pass the copy to this method.</p>
		 * <p>
		 * Every bit of the returned byte array will be part of the hash
		 * result.</p>
		 *
		 * @param messageLengthInBits the number of bits in the given byte array
		 * to be considered part of the message to be hashed. Cannot be
		 * negative, and must not be larger than the total number of bits made
		 * available in the given byte array.
		 * @param message a byte array which contains all of the message bits,
		 * and possibly subsequent unwanted bits. Must not be {@code null}.
		 * @return a byte array which contains the calculated hash.
		 */
		public byte[] apply(int messageLengthInBits, byte[] message) {
			Objects.requireNonNull(message);
			if (messageLengthInBits < 0) {
				throw new IllegalArgumentException(
						"messageLengthInBits cannot be negative.");
			}
			if (messageLengthInBits > message.length * 8) {
				throw new IllegalArgumentException(
						"messageLengthInBits cannot be greater than the length of the byte array.");
			}
			return getSpongeFunction().apply(messageLengthInBits, message);
		}

		/**
		 * Applies this hash function to every byte returned by the given {@code
		 * InputStream} and returns the calculated hash result. Every bit read
		 * from the stream will be considered to be part of the message to be
		 * hashed. Every bit of the returned byte array will be part of the hash
		 * result.
		 *
		 * @param stream an {@code InputStream} from which the message bits
		 * should be read. Must not be {@code null}.
		 * @return a byte array which contains the calculated hash.
		 * @throws IOException if an {@code IOException} is thrown by any of the
		 * stream reading operations.
		 */
		public byte[] apply(InputStream stream) throws IOException {
			Objects.requireNonNull(stream);
			return getSpongeFunction().apply(stream);
		}

		@Override
		public String toString() {
			StringBuilder sb = new StringBuilder(7);
			sb.append("SHA3-");
			sb.append(outputLengthInBits);
			return sb.toString();
		}
	}

	/**
	 * The SHAKE extendable-output functions (XOFs) defined by NIST in FIPS PUB
	 * 202. Each of the SHAKE extendable-output functions can take an arbitrary
	 * output length. The plain SHAKE XOFs use a domain suffix of "1111", and
	 * the RawSHAKE XOFs use a domain suffix of "11". The domain suffix
	 * distinguishes these two function types from each other and from other
	 * applications of the
	 * <span style="font-variant: small-caps">Keccak</span> sponge function.
	 * <p>
	 * Note that {@code ExtendableOutputFunction} objects cannot be directly
	 * used to calculate a message hash, because the NIST XOF definitions do not
	 * in themselves specify a hash output length. Instead, an
	 * {@code ExtendableOutputFunction} object can be used to create a
	 * {@code KeccakSponge} object with the desired XOF specification for a
	 * chosen output length, and the {@code KeccakSponge} object is then used to
	 * calculate message hashes. For example:
	 * <pre>{@code
	 *     KeccakSponge spongeFunction = FIPS202.ExtendableOutputFunction.
	 *             SHAKE256.withOutputLength(4096);
	 *     byte[] hash = spongeFunction.apply(message);
	 * }</pre>
	 * </p>
	 *
	 * @see HashFunction
	 * @see KeccakSponge
	 */
	public enum ExtendableOutputFunction {
		/**
		 * The SHAKE128 extendable-output function, with a security level of 128
		 * bits, and able to generate an arbitrarily chosen output length. The
		 * domain suffix is "1111".
		 */
		SHAKE128((short) 1344, (short) 256, "1111"),
		/**
		 * The SHAKE256 extendable-output function, with a security level of 256
		 * bits, and able to generate an arbitrarily chosen output length. The
		 * domain suffix is "1111".
		 */
		SHAKE256((short) 1088, (short) 512, "1111"),
		/**
		 * The RawSHAKE128 extendable-output function, with a security level of
		 * 128 bits, and able to generate an arbitrarily chosen output length.
		 * The domain suffix is "11".
		 */
		RawSHAKE128((short) 1344, (short) 256, "11"),
		/**
		 * The RawSHAKE256 extendable-output function, with a security level of
		 * 256 bits, and able to generate an arbitrarily chosen output length.
		 * The domain suffix is "11".
		 */
		RawSHAKE256((short) 1088, (short) 512, "11");

		private final short bitrate;
		private final short capacity;
		private final String suffixBits;

		private ExtendableOutputFunction(short r, short c, String suffixBits) {
			bitrate = r;
			capacity = c;
			this.suffixBits = suffixBits;
		}

		/**
		 * Returns a {@code KeccakSponge} with the specified output length for
		 * this extendable-output function. The returned object can be shared
		 * and reused as often as needed.
		 *
		 * @param outputLengthInBits the hash output length in bits.
		 * @return a {@code KeccakSponge} object which represents this XOF with
		 * the specified output length.
		 */
		public KeccakSponge withOutputLength(int outputLengthInBits) {
			if (outputLengthInBits < 1) {
				throw new IllegalArgumentException(
						"outputLengthInBits must be greater than zero.");
			}
			return new KeccakSponge(bitrate, capacity, suffixBits,
					outputLengthInBits);
		}

		@Override
		public String toString() {
			return this.name();
		}
	}

	/**
	 * Returns a hexadecimal representation of the given byte array. This
	 * conversion is based on the logic found in
	 * <a href="http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf">FIPS
	 * PUB 202</a> in appendix "B.1 Conversion Functions".
	 * <p>
	 * The first hexadecimal digit pair in the returned {@code String} will
	 * represent the byte at index zero of the given array. The first
	 * hexadecimal digit in each pair represents the value of the
	 * most-significant four bits of the corresponding byte, and the second
	 * hexadecimal digit in each pair represents the value of the
	 * least-significant four bits of that same byte.</p>
	 *
	 * @param bytes the byte array, which can be empty but must not be
	 * {@code null}.
	 * @return a {@code String} which contains two hex digits for every byte in
	 * the given array.
	 */
	public static String hexFromBytes(byte[] bytes) {
		Objects.requireNonNull(bytes, "Parameter `bytes` cannot be null.");
		StringBuilder hexString = new StringBuilder(bytes.length * 2);
		for (byte b : bytes) {
			appendByteAsHexPair(b, hexString);
		}
		return hexString.toString();
	}

	private static void appendByteAsHexPair(byte b, StringBuilder sb) {
		assert sb != null;
		byte leastSignificantHalf = (byte) (b & 0x0f);
		byte mostSignificantHalf = (byte) ((b >> 4) & 0x0f);
		sb.append(getHexDigitWithValue(mostSignificantHalf));
		sb.append(getHexDigitWithValue(leastSignificantHalf));
	}

	private static char getHexDigitWithValue(byte value) {
		assert value >= 0 && value <= 16;
		if (value < 10) {
			return (char) ('0' + value);
		}
		return (char) ('A' + value - 10);
	}

	/**
	 * Returns a hexadecimal {@code String} representation of the given binary
	 * bit string. This method is based on the logic described in
	 * <a href="http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf">FIPS
	 * PUB 202</a> in appendix "B.1 Conversion Functions", in particular
	 * "Algorithm 11: b2h(S)".
	 * <p>
	 * The bit string is such that the least-significant bits come first, so
	 * where this method is concerned the bit string "0001" represents the
	 * decimal value 8 (0*2^0 + 0*2^1 + 0*2^2 + 1*2^3). The returned hexadecimal
	 * is such that the first hex pair represents the value of the first eight
	 * bits of the bit string (or fewer if the length of the bit string is less
	 * than eight), and the first first hexadecimal digit of each pair
	 * represents the value of the most-significant four bits, and the second
	 * hexadecimal digit represents the value of the least-significant four
	 * digits. If the total length of the bit string is not exactly divisible by
	 * eight then the final hex pair will represent the bit string as though it
	 * was filled with zero bits up to the length of the next whole byte.</p>
	 * <p>
	 * The given bit string can be any length, but the returned hexadecimal
	 * representation will always contain a multiple of hex pairs. If the bit
	 * string is empty then the returned hexadecimal string will be empty.</p>
	 *
	 * @param bitString a {@code String} which contains only '0' and '1' binary
	 * digits. Can be empty, but must not be {@code null}.
	 * @return a {@code String} which contains a hexadecimal representation of
	 * the given binary.
	 */
	public static String hexFromBinary(String bitString) {
		Objects.requireNonNull(bitString,
				"Parameter `bitString` must not be null.");
		StringBuilder hexString = new StringBuilder(
				(bitString.length() + 8 - 1) / 8);
		for (int bitIndex = 0; bitIndex < bitString.length(); bitIndex += 8) {
			byte byteValue = byteValueOfBinaryAtIndex(bitIndex, bitString);
			appendByteAsHexPair(byteValue, hexString);
		}
		return hexString.toString();
	}

	private static byte byteValueOfBinaryAtIndex(int bitIndex, String bitString) {
		int bitsRemaining = bitString.length() - bitIndex;
		int byteBitStopIndex = Math.min(8, bitsRemaining);
		byte byteValue = (byte) 0;
		for (int byteBitIndex = 0; byteBitIndex < byteBitStopIndex;
				++byteBitIndex) {
			if (bitString.charAt(bitIndex + byteBitIndex) == '0') {
				continue;
			}
			byteValue += (byte) (1 << byteBitIndex);
		}
		return byteValue;
	}

	/**
	 * Returns a byte array which represents the given hexadecimal string. This
	 * conversion is based on the logic found in
	 * <a href="http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf">FIPS
	 * PUB 202</a> in appendix "B.1 Conversion Functions".
	 * <p>
	 * The hexadecimal string provided to this method must be an even number of
	 * hexadecimal digits [0-9A-F] (case insensitive), such that each hex pair
	 * will represent one byte in the returned array. An empty string will lead
	 * to an empty byte array being returned.</p>
	 * <p>
	 * The byte at index zero of the returned array will take its value from the
	 * first hexadecimal digit pair in the given {@code String}. The first
	 * hexadecimal digit in each pair represents the value of the
	 * most-significant four bits of the corresponding byte, and the second
	 * hexadecimal digit in each pair represents the value of the
	 * least-significant four bits of that same byte.</p>
	 *
	 * @param hex a {@code String} which contains an even number of hexadecimal
	 * digits. Can be empty but must not be {@code null}.
	 * @return an array of byte values based on the provided hexadecimal string.
	 */
	public static byte[] bytesFromHex(String hex) {
		Objects.requireNonNull(hex, "Parameter `hex` cannot be null.");
		int hexLength = hex.length();
		if (hexLength % 2 != 0) {
			throw new IllegalArgumentException(
					"Hexadecimal string must be composed of hexadecimal pairs.");
		}
		byte[] bytes = new byte[hexLength / 2];
		for (int charIndex = 0; charIndex < hexLength; charIndex += 2) {
			bytes[charIndex / 2] = byteValueOfHexPairAtIndex(hex, charIndex);
		}
		return bytes;
	}

	private static byte byteValueOfHexPairAtIndex(String hex, int charIndex) {
		assert hex != null;
		assert charIndex >= 0;
		char mostSignificantHexDigit = hex.charAt(charIndex);
		byte hexPairValue = (byte) (16
				* valueOfHexDigit(mostSignificantHexDigit));
		char leastSignificantHexDigit = hex.charAt(charIndex + 1);
		hexPairValue += valueOfHexDigit(leastSignificantHexDigit);
		return hexPairValue;
	}

	private static byte valueOfHexDigit(char hexDigit) {
		if ('0' <= hexDigit && hexDigit <= '9') {
			return (byte) (hexDigit - '0');
		}
		if ('A' <= hexDigit && hexDigit <= 'F') {
			return (byte) (10 + hexDigit - 'A');
		}
		if ('a' <= hexDigit && hexDigit <= 'f') {
			return (byte) (10 + hexDigit - 'a');
		}
		throw new IllegalArgumentException(
				"hexDigit must be from character set [0-9A-F] (case insensitive).");
	}

	/**
	 * Returns a bit string representation of the given hexadecimal
	 * {@code String}, with exactly the specified number of bits. This method is
	 * based on the logic described in
	 * <a href="http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf">FIPS
	 * PUB 202</a> in appendix "B.1 Conversion Functions", in particular
	 * "Algorithm 10: h2b(H, n)".
	 * <p>
	 * The hexadecimal will be read so that the first hex pair generates the
	 * first eight bits of the resulting bit string (or fewer if the requested
	 * bit limit is less than eight bits). The first hexadecimal digit of the
	 * pair determines the most-significant four bits, and the second
	 * hexadecimal digit the least-significant four bits.</p>
	 * <p>
	 * The returned bit string will be formed such that the least-significant
	 * bits come first, so where this method is concerned the bit string "0001"
	 * represents the decimal value 8 (0*2^0 + 0*2^1 + 0*2^2 + 1*2^3). As an
	 * example, the hex "21" will generate bit string "10000100" (assuming the
	 * full bit limit of 8 has been specified).</p>
	 * <p>
	 * If the specified bit limit is less than the number of bits which could be
	 * represented by the given hexadecimal string, then the returned bit string
	 * will represent only some initial portion of the hex string (left-most hex
	 * digits first, least significant bits first). If the specified bit limit
	 * is zero then this method will return an empty {@code String}.</p>
	 *
	 * @param hex a {@code String} which contains any number of hex digit pairs,
	 * so that the number of hex digits must be even. Can be empty but must not
	 * be {@code null}.
	 * @param bitLimit the length in bits of the generated bit string. Must not
	 * be negative, and must not be greater than the maximum number of bits
	 * which can be represented by the given hex string.
	 * @return a {@code String} representing a bit string of exactly the length
	 * given by {@code bitLimit}.
	 */
	public static String binaryFromHex(String hex, int bitLimit) {
		validateHexString(hex);
		validateBitLimit(hex, bitLimit);
		int byteLimit = (bitLimit + 8 - 1) / 8;
		int hexDigitLimit = byteLimit * 2;
		StringBuilder bitString = new StringBuilder(bitLimit);
		for (int hexCharIndex = 0, bitsSoFar = 0;
				hexCharIndex < hexDigitLimit && bitsSoFar < bitLimit;
				hexCharIndex += 2, bitsSoFar += 8) {
			byte hexPairValue = byteValueOfHexPairAtIndex(hex, hexCharIndex);
			int bitsRequiredFromHexPair = Math.min(8, bitLimit - bitsSoFar);
			appendBitsFromByte(hexPairValue, bitsRequiredFromHexPair, bitString);
		}
		return bitString.toString();
	}

	private static void validateHexString(String hex) {
		Objects.requireNonNull(hex, "Parameter `hex` cannot be null.");
		int hexLength = hex.length();
		if (hexLength % 2 != 0) {
			throw new IllegalArgumentException(
					"String `hex` must contain an even number of hex digits.");
		}
		for (int charIndex = 0; charIndex < hexLength; ++charIndex) {
			char hexDigit = hex.charAt(charIndex);
			if (!isValidHexDigit(hexDigit)) {
				throw new IllegalArgumentException(
						"String `hex` can only contain hex digits [0-9A-F] (case insensitive).");
			}
		}
	}

	private static void validateBitLimit(String hex, int bitLimit) {
		if (bitLimit < 0) {
			throw new IllegalArgumentException("bitLimit cannot be negative.");
		}
		if (bitLimit > hex.length() * Byte.SIZE / 2) {
			throw new IllegalArgumentException(
					"bitLimit cannot exceed the number of bits represented by the hex string.");
		}
	}

	private static boolean isValidHexDigit(char hexDigit) {
		if ('0' <= hexDigit && hexDigit <= '9') {
			return true;
		}
		if ('A' <= hexDigit && hexDigit <= 'F') {
			return true;
		}
		if ('a' <= hexDigit && hexDigit <= 'f') {
			return true;
		}
		return false;
	}

	private static void appendBitsFromByte(byte value, int bitsRequired,
			StringBuilder bitString) {
		for (byte bitIndex = 0; bitIndex < bitsRequired; ++bitIndex) {
			boolean bitHigh = (value & (byte) (1 << bitIndex)) != 0;
			bitString.append(bitHigh ? '1' : '0');
		}
	}
}
