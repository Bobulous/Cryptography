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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.UnaryOperator;

/**
 * The <b><span style="font-variant: small-caps">Keccak</span> sponge
 * function</b> for cryptographic hashing.
 * <p>
 * An object of this type is immutable, and can be freely shared and reused.
 * </p>
 * <p>
 * The sponge function represented by this code is entirely based on the
 * <a href="http://keccak.noekeon.org/"><span style="font-variant: small-caps">Keccak</span>
 * sponge function family</a>
 * created by <cite>Guido Bertoni, Joan Daemen, Michaël Peeters, and Gilles Van
 * Assche</cite>. Detailed specifications are defined by <b>The
 * <span style="font-variant: small-caps">Keccak</span> Reference version
 * 3.0</b>
 * [January 2011].
 * </p>
 * <p>
 * The <span style="font-variant: small-caps">Keccak</span> sponge function
 * powers the SHA-3 hash functions, and the related SHAKE extended output
 * functions, both standardised by
 * <a href="http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf">FIPS PUB
 * 202</a> [August 2015]. For convenience, these standardised instances of the
 * <span style="font-variant: small-caps">Keccak</span> sponge function have
 * been made available in the companion class {@link FIPS202}.
 * </p>
 *
 * @author Bobulous <http://www.bobulous.org.uk/>
 * @see FIPS202
 */
public final class KeccakSponge implements UnaryOperator<byte[]> {

	/**
	 * The set of valid values for the permutation width. The width is the total
	 * number of bits in the Keccak state (the sum of the bitrate and the
	 * capacity).
	 */
	private static final Set<Short> VALID_WIDTHS;

	static {
		Set<Short> widths = new HashSet<>(16);
		widths.addAll(Arrays.asList(new Short[]{
			25,
			50,
			100,
			200,
			400,
			800,
			1600
		}));
		VALID_WIDTHS = Collections.unmodifiableSet(widths);
	}

	private final short bitrate;
	private final short capacity;
	private final byte laneLength;
	private final int outputLengthInBits;

	/**
	 * Suffix bits which define a hash application "domain".
	 * <p>
	 * This concept does not appear to be found within the
	 * <a href="http://keccak.noekeon.org/Keccak-reference-3.0.pdf">Keccak
	 * Reference v3.0</a>, but is found in
	 * <a href="http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf">FIPS
	 * PUB 202</a> and in the summary
	 * <a href="http://keccak.noekeon.org/specs_summary.html">The Keccak sponge
	 * function family: Specifications summary</a>.</p>
	 */
	private final String suffixBits;

	/**
	 * Returns the bitrate of this {@code KeccakSponge} instance. The bitrate is
	 * the (maximum) number of bits within each block absorbed into or squeezed
	 * from the permutation state. After the absorption or squeezing of each
	 * block, the state is permuted using the
	 * <span style="font-variant: small-caps">Keccak</span>-F algorithm.
	 *
	 * @return the bitrate in bits.
	 */
	public int getBitrate() {
		return bitrate;
	}

	/**
	 * Returns the capacity of this {@code KeccakSponge} instance. The capacity
	 * is the size, in bits, of the portion of the permutation state which is
	 * not modified by the absorption of a new input block (at least not
	 * immediately), and which is not copied in the squeezing of a new output
	 * block, but which is affected when the state is permuted.
	 *
	 * @return the capacity in bits.
	 */
	public int getCapacity() {
		return capacity;
	}

	/**
	 * Returns the permutation width of this {@code KeccakSponge} instance. The
	 * width is the size of the permutation state in bits, and is equal to the
	 * sum of the bitrate and the capacity.
	 *
	 * @return the permutation width in bits.
	 */
	public int getPermutationWidth() {
		return bitrate + capacity;
	}

	/**
	 * Returns the lane length of this {@code KeccakSponge} instance. The
	 * permutation state is composed of a 5×5 array of "lanes". The length of
	 * each lane is therefore the permutation state width divided by
	 * twenty-five.
	 *
	 * @return the length in bits of each lane.
	 */
	public int getLaneLength() {
		return laneLength;
	}

	/**
	 * Returns the number of rounds per permutation of this {@code KeccakSponge}
	 * instance. When the Keccak state is permuted it executes a "round" of
	 * transformations (named theta, rho, pi, chi, and iota) multiple times. The
	 * number of rounds in each permutation depends upon the permutation width,
	 * and will be a quantity between twelve and twenty-four.
	 *
	 * @return the number of rounds in each permutation.
	 */
	public int getNumberOfRoundsPerPermutation() {
		return KeccakUtilities.getNumberOfRoundsPerPermutationWithLaneLength(
				laneLength);
	}

	/**
	 * Returns the domain suffix used by this {@code KeccakSponge} instance. The
	 * domain suffix is optional, but if a suffix is being used then it will be
	 * a {@code String} representing a bitstring (composed of only '0' and '1'
	 * digits) which will be appended to the input after the message bits but
	 * before the padding bits, prior to the start of the hash processing.
	 * <p>
	 * Use of a domain suffix allows different Keccak applications to
	 * differentiate themselves. For example, SHA3 hash functions use a domain
	 * suffix of "01", SHAKE extendable-output functions use a domain suffix of
	 * "1111", and RawSHAKE uses "11". If this {@code KeccakSponge} instance
	 * does not use a domain suffix then this method will return
	 * {@code Optional.empty()}.</p>
	 *
	 * @return the domain suffix as an {@code Optional<String>}.
	 */
	public Optional<String> getSuffixBits() {
		if (suffixBits.isEmpty()) {
			return Optional.empty();
		} else {
			return Optional.of(suffixBits);
		}
	}

	/**
	 * Returns the length of the hash result which will be generated by this
	 * {@code KeccakSponge}.
	 *
	 * @return the output length in bits.
	 */
	public int getOutputLengthInBits() {
		return outputLengthInBits;
	}

	/**
	 * Constructs a Keccak sponge function with the given parameters. The
	 * resulting {@code KeccakSponge} object is immutable and can be safely
	 * shared and reused.
	 * <p>
	 * The bitrate is the maximum number of bits in each block while absorbing
	 * the input message into the Keccak sponge, and while squeezing the sponge
	 * to generate the resulting hash result. After each block has been absorbed
	 * or squeezed, the Keccak sponge state will be permuted.
	 * (<strong>NOTICE</strong>: Currently support is only implemented for
	 * bitrates which are exactly divisible by 8.)</p>
	 * <p>
	 * The capacity is the number of additional bits (on top of the bitrate) in
	 * the sponge permutation state. The sum of the bitrate and the capacity is
	 * the total "width" of the sponge permutation state. The state width must
	 * be any of the values 25, 50, 100, 200, 400, 800, or 1600, and so the sum
	 * of the bitrate and the capacity must be equal to one of these valid
	 * widths. (<strong>NOTICE</strong>: Currently support is only implemented
	 * for widths of 200 or greater.)
	 * </p>
	 * <p>
	 * The suffix bitstring (or "domain suffix") will be appended to any input
	 * message processed by this sponge function. Using a domain suffix allows
	 * different results to be returned for different applications, even when
	 * the input message and all other parameters are identical. For example,
	 * the SHA-3 hash functions all use a domain suffix of "01", the SHAKE
	 * extendable output functions use a domain suffix of "1111", and the
	 * RawSHAKE extendable output functions use a domain suffix of "11".
	 * </p>
	 * <p>
	 * The output length determines the length, in bits, of the hash result
	 * which will be generated. The output length can be any non-zero size, and
	 * the sponge will be squeezed repeatedly until the hash result is of the
	 * requested length. Bear in mind that (all other parameters remaining
	 * identical) varying the output length will change only the later bits of
	 * the hash result. For example, if using output length 256 and then output
	 * length 512, the first 256 bits will be identical in both hash results.
	 * For this reason, it is recommended that you not use different output
	 * lengths for the same input message. See
	 * <a href="http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf">NIST
	 * FIPS PUB 202</a> "Appendix A.2 Additional Consideration for
	 * Extendable-Output Functions" for a note about this.</p>
	 *
	 * @param bitrate must be a number of bits greater than zero.
	 * @param capacity must be a number of bits, greater than zero, such that
	 * the sum {@code bitrate + capacity} is a valid Keccak state "width".
	 * @param suffixBits a {@code String} which can contain only digits "0" and
	 * "1". Can be an empty {@code String} if no domain suffix is required. Must
	 * not be {@code null}.
	 * @param outputLength the hash output length in bits. Must be greater than
	 * zero.
	 * @throws NullPointerException if the {@code suffixBits} parameter is
	 * {@code null}.
	 * @throws IllegalArgumentException if any of the parameters has been
	 * provided with an invalid value.
	 */
	public KeccakSponge(int bitrate, int capacity, String suffixBits,
			int outputLength) {
		validateBitrate(bitrate);
		validateCapacity(capacity);
		validateSuffixBits(suffixBits);
		validateOutputLength(outputLength);
		short width = (short) (bitrate + capacity);
		validatePermutationWidth(width);
		this.bitrate = (short) bitrate;
		this.capacity = (short) capacity;
		this.suffixBits = suffixBits;
		this.laneLength = (byte) (width / 25);
		this.outputLengthInBits = outputLength;
	}

	/**
	 * Applies this Keccak sponge function to the given message and returns the
	 * calculated hash result. Every bit contained by the byte array will be
	 * considered part of the input message. The returned byte array will
	 * contain all of the bits of the calculated hash.
	 * <p>
	 * The given message byte array will not be modified by this method.
	 * However, to avoid problems, the message byte array should not be
	 * accessible to any other threads while it is being used to calculate the
	 * hash. If the message comes from a shared resource then take a copy and
	 * pass the copy to this method.</p>
	 * <p>
	 * The length, in bits, of the resulting hash will be equal to the output
	 * length configured for this {@code KeccakSponge} object, as returned by
	 * the method {@link #getOutputLengthInBits()}. If the output length is not
	 * exactly divisible by eight then the last few bits of the final byte of
	 * the returned byte array will not be part of the hash result binary. For
	 * example, if the output length is 10 bits then this method will return a
	 * byte array which contains two bytes, and only the two least-significant
	 * bits of the second byte will actually be part of the hash result; the
	 * most-significant six bits of the second byte will <strong>not</strong> be
	 * part of the hash result binary.</p>
	 *
	 * @param message a byte array which exactly represents the message. Must
	 * not be {@code null}.
	 * @return a byte array which contains the calculated hash.
	 */
	@Override
	public byte[] apply(byte[] message) {
		return apply(message.length * Byte.SIZE, message);
	}

	/**
	 * Applies this Keccak sponge function to the specified number of bits from
	 * the given message byte array and returns the calculated hash result. Only
	 * the first {@code messageLengthInBits} bits found within the provided
	 * {@code message} will be considered part of the input message to be
	 * hashed, and any subsequent bits will be ignored.
	 * <p>
	 * Bits are taken first from the bytes with the lowest index, and from the
	 * bits with the lowest binary indices. For example, if the given message
	 * byte array contains two bytes, and the specified message length is ten
	 * bits, then all of the byte at array index zero will be included, and from
	 * the second byte only the bits at index zero (the least significant bit)
	 * and index one will be included. The most-significant six bits of the
	 * second byte will be ignored.</p>
	 * <p>
	 * The given message byte array will not be modified by this method.
	 * However, to avoid problems, the message byte array should not be
	 * accessible to any other threads while it is being used to calculate the
	 * hash. If the message comes from a shared resource then take a copy and
	 * pass the copy to this method.</p>
	 * <p>
	 * The length, in bits, of the resulting hash will be equal to the output
	 * length configured for this {@code KeccakSponge} object, as returned by
	 * the method {@link #getOutputLengthInBits()}. If the output length is not
	 * exactly divisible by eight then the last few bits of the final byte of
	 * the returned byte array will not be part of the hash result binary. For
	 * example, if the output length is 10 bits then this method will return a
	 * byte array which contains two bytes, and only the two least-significant
	 * bits of the second byte will actually be part of the hash result; the
	 * most-significant six bits of the second byte will <strong>not</strong> be
	 * part of the hash result binary.</p>
	 *
	 * @param messageLengthInBits the number of bits in the given byte array to
	 * be considered part of the message to be hashed. Must not be negative, and
	 * must not be larger than the total number of bits available in the given
	 * byte array.
	 * @param message a byte array which contains all of the message bits, and
	 * possibly subsequent unwanted bits. Must not be {@code null}.
	 * @return a byte array which contains the calculated hash.
	 */
	public byte[] apply(int messageLengthInBits, byte[] message) {
		validateMessageLength(message, messageLengthInBits);
		int inputLengthInBits = calculateTotalInputLength(messageLengthInBits);
		byte[] input = createSufficientlyLargeByteArray(inputLengthInBits);
		moveMessageBitsIntoInput(message, messageLengthInBits, input);
		appendDomainSuffixToInput(input, messageLengthInBits);
		padInput(input, messageLengthInBits);
		KeccakState state = createKeccakStateForLength(laneLength);
		state.absorb(input, inputLengthInBits, bitrate);
		byte[] hash = state.squeeze(bitrate, outputLengthInBits);
		return hash;
	}

	private KeccakState createKeccakStateForLength(int laneLength) {
		switch (laneLength) {
			case 64:
				return new KeccakState1600();
			case 32:
				return new KeccakState800();
			case 16:
				return new KeccakState400();
			case 8:
				return new KeccakState200();
			default:
				throw new UnsupportedOperationException(
						"Permutation width currently not supported.");
		}
	}

	/**
	 * Applies this Keccak sponge function to every byte returned by the given
	 * {@code InputStream} and returns the calculated hash result. Every bit
	 * from every byte read from the stream will be considered to be part of the
	 * input message to be hashed.
	 * <p>
	 * This method will return the hash result as a byte array. The length, in
	 * bits, of the resulting hash will be equal to the output length configured
	 * for this {@code KeccakSponge} object, as returned by the method
	 * {@link #getOutputLengthInBits()}. If the output length is not exactly
	 * divisible by eight then the last few bits of the final byte of the
	 * returned byte array will not be part of the hash result binary. For
	 * example, if the output length is 10 bits then this method will return a
	 * byte array which contains two bytes, and only the two least-significant
	 * bits of the second byte will actually be part of the hash result; the
	 * most-significant six bits of the second byte will <strong>not</strong> be
	 * part of the hash result binary.</p>
	 *
	 * @param stream an {@code InputStream} from which the message bytes should
	 * be read. Must not be {@code null}.
	 * @return a byte array which contains the calculated hash.
	 * @throws IOException if an {@code IOException} is thrown by any of the
	 * stream reading operations.
	 */
	public byte[] apply(InputStream stream) throws IOException {
		// TODO: Add support for cases where bitrate is not divisible by 8.
		requireWholeByteBitrate(bitrate);
		Objects.requireNonNull(stream);
		KeccakState state = createKeccakStateForLength(laneLength);
		byte[] block = createSufficientlyLargeByteArray(bitrate);
		int finalBlockMessageBits = absorbInitialStreamBlocksIntoState(stream,
				block, state);
		byte[] finalBlock = prepareFinalBlockArray(finalBlockMessageBits, block);
		appendDomainSuffixToInput(finalBlock, finalBlockMessageBits);
		padInput(finalBlock, finalBlockMessageBits);
		state.absorb(finalBlock, finalBlock.length * Byte.SIZE, bitrate);
		byte[] hash = state.squeeze(bitrate, outputLengthInBits);
		return hash;
	}

	/**
	 * Calculates the total length of the input that will be absorbed into the
	 * Keccak sponge, including the input message bits, any domain suffix bits,
	 * and the pad10*1 padding bits.
	 * <p>
	 * The returned result will be greater than zero and will be a multiple of
	 * the specified bitrate.</p>
	 *
	 * @param messageLengthInBits the total number of bits in the original input
	 * message. Must not be negative.
	 * @return the total length, in bits, of the input binary which will be
	 * processed by this Keccak sponge function.
	 */
	private int calculateTotalInputLength(int messageLengthInBits) {
		assert messageLengthInBits >= 0;
		int minimumPaddedLength = calculateMinimumLengthAfterPadding(
				messageLengthInBits);
		if (minimumPaddedLength % bitrate == 0) {
			return minimumPaddedLength;
		} else {
			return minimumPaddedLength + bitrate - minimumPaddedLength % bitrate;
		}
	}

	/*
	 * Returns the minimum length once message bits, suffix bits, and high
	 * padding bits are counted.
	 */
	private int calculateMinimumLengthAfterPadding(int messageLengthInBits) {
		// The padding always starts and ends with a high '1' bit, so the
		// padding length will always be at least two bits.
		return messageLengthInBits + suffixBits.length() + 2;
	}

	/**
	 * Appends the domain suffix bits, if any, to the given input array, at the
	 * first bit index which comes after the input message bits.
	 *
	 * @param input a byte array which already contains the message bits.
	 * @param suffixStartBitIndex the bit index immediately following the final
	 * message bit index.
	 */
	private void appendDomainSuffixToInput(byte[] input, int suffixStartBitIndex) {
		assert input != null;
		assert suffixStartBitIndex >= 0;
		assert suffixBits != null;
		for (int suffixBitIndex = 0; suffixBitIndex < suffixBits.length();
				++suffixBitIndex) {
			boolean suffixBitHigh = suffixBits.charAt(suffixBitIndex) == '1';
			if (suffixBitHigh) {
				int targetInputBit = suffixStartBitIndex + suffixBitIndex;
				int targetInputByte = targetInputBit / Byte.SIZE;
				int targetInputByteBitIndex = targetInputBit % Byte.SIZE;
				input[targetInputByte] += 1 << targetInputByteBitIndex;
			}
		}
	}

	/**
	 * Applies pad10*1 (multi-rate padding) to the end of the binary held in the
	 * input array. This padding guarantees that the final input binary length
	 * will be non-zero and will be a multiple of the specified bitrate.
	 *
	 * @param input a byte array which already contains the message bits and any
	 * suffix bits.
	 * @param messageLengthInBits the length of the original message in bits
	 * (not including any domain suffix bits).
	 */
	private void padInput(byte[] input, int messageLengthInBits) {
		assert input != null;
		assert messageLengthInBits >= 0;
		int lengthOfMessageWithSuffix = messageLengthInBits + suffixBits.
				length();
		int zeroPaddingBitsRequired = calculateZeroPaddingBitsRequired(
				messageLengthInBits);
		int padStartIndex = lengthOfMessageWithSuffix;
		int padEndIndex = lengthOfMessageWithSuffix + 1
				+ zeroPaddingBitsRequired;
		setInputBitHigh(input, padStartIndex);
		setInputBitHigh(input, padEndIndex);
	}

	private int calculateZeroPaddingBitsRequired(int messageLengthInBits) {
		int bitsIncludingPadEnds = calculateMinimumLengthAfterPadding(
				messageLengthInBits);
		int zeroPaddingBitsRequired;
		if (bitsIncludingPadEnds % bitrate == 0) {
			zeroPaddingBitsRequired = 0;
		} else {
			zeroPaddingBitsRequired = bitrate - bitsIncludingPadEnds % bitrate;
		}
		return zeroPaddingBitsRequired;
	}

	private void setInputBitHigh(byte[] input, int inputBitIndex) {
		assert input != null;
		assert inputBitIndex >= 0;
		int inputByteIndex = inputBitIndex / Byte.SIZE;
		byte outputByteBitIndex = (byte) (inputBitIndex % Byte.SIZE);
		byte byteBitValue = (byte) (1 << outputByteBitIndex);
		input[inputByteIndex] += byteBitValue;
	}

	/**
	 * Reads as many {@code bitrate}-sized blocks as possible from the given
	 * {@code InputStream} and returns the total number of bits read from the
	 * stream. After each block is read from the stream, it is absorbed into the
	 * given {@code KeccakState}.
	 * <p>
	 * If the final read contains a number of bits which is less than
	 * {@code bitrate} then this method halts and does not absorb those bits
	 * into the state. The calling method must use the {@code block} array and
	 * the returned number of read bits in order to make sure that these
	 * remaining bits are absorbed into the permutation state.</p>
	 *
	 * @param stream an {@code InputStream} which provides the input message
	 * bytes.
	 * @param block the array into which each bitrate-sized block of message
	 * bits should be read.
	 * @param state the {@code KeccakState} being used for the hash calculation.
	 * @return the total number of bits read from the stream.
	 * @throws IOException
	 */
	private int absorbInitialStreamBlocksIntoState(InputStream stream,
			byte[] block, KeccakState state) throws IOException {
		assert stream != null;
		assert block != null;
		assert state != null;
		int bitsInCurrentBlock = readBlockFromStream(stream, block);
		while (bitsInCurrentBlock == bitrate) {
			state.absorbBitsIntoState(block, 0, bitsInCurrentBlock);
			state.permute();
			bitsInCurrentBlock = readBlockFromStream(stream, block);
		}
		return bitsInCurrentBlock;
	}

	/**
	 * Repeatedly reads from the given {@code InputStream} until either the
	 * stream ends, or the provided byte array has been filled with a whole
	 * block.
	 *
	 * @param stream an {@code InputStream} which provides the input message
	 * bytes.
	 * @param block the array into which the message bytes should be read.
	 * @return the total number of bits which were filled in the {@code block}
	 * array. If the stream ends then this number may be lower than the the size
	 * of the array, and the remainder of the array will be filled with zero
	 * bits.
	 * @throws IOException if an {@code IOException} is thrown by any of the
	 * stream reading operations.
	 */
	private int readBlockFromStream(InputStream stream, byte[] block) throws
			IOException {
		assert block != null;
		assert block.length * Byte.SIZE == bitrate;
		assert stream != null;
		int filledBytes = 0;
		int readBytes = stream.read(block);
		while (readBytes > 0) {
			filledBytes += readBytes;
			readBytes = stream.read(block, filledBytes, block.length
					- filledBytes);
		}
		if (filledBytes < block.length) {
			Arrays.fill(block, filledBytes, block.length, (byte) 0);
		}
		return filledBytes * Byte.SIZE;
	}

	/**
	 * Returns an array which is large enough to hold the final message bits
	 * (read from an {@code InputStream}), and any suffix bits, and the pad10*1
	 * padding bits.
	 *
	 * @param finalBlockMessageLengthInBits the number of message bits in the
	 * final block which was read from the stream.
	 * @param finalBlock the byte array which holds the final message bits.
	 * @return a byte array which is sufficiently large to hold all of the final
	 * message bits, suffix bits, and padding.
	 */
	private byte[] prepareFinalBlockArray(int finalBlockMessageLengthInBits,
			byte[] finalBlock) {
		assert finalBlockMessageLengthInBits >= 0;
		assert finalBlock != null;
		int minimumLengthAfterPadding = calculateMinimumLengthAfterPadding(
				finalBlockMessageLengthInBits);
		if (minimumLengthAfterPadding <= bitrate) {
			// The existing byte array is large enough so simply return it.
			return finalBlock;
		} else {
			return resizedFinalBlockArray(finalBlockMessageLengthInBits,
					finalBlock, minimumLengthAfterPadding);
		}
	}

	private byte[] resizedFinalBlockArray(int finalBlockMessageLengthInBits,
			byte[] finalBlock, int minimumLengthAfterPadding) {
		int blocksRequired
				= divideThenRoundUp(minimumLengthAfterPadding, bitrate);
		byte[] finalBlocks = new byte[blocksRequired * bitrate / Byte.SIZE];
		int bytesToCopy = divideThenRoundUp(finalBlockMessageLengthInBits,
				Byte.SIZE);
		System.arraycopy(finalBlock, 0, finalBlocks, 0, bytesToCopy);
		return finalBlocks;
	}

	/**
	 * Returns a summary of this Keccak sponge function. Do not rely on the
	 * format of the returned text; it may change in future. All of the data
	 * found in the summary can be retrieved directly from this object using
	 * dedicated methods, so there should never be any need to parse data out of
	 * the text returned by this method.
	 *
	 * @return a {@code String} which summarises the settings of this
	 * {@code KeccakSponge}.
	 */
	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder(64);
		sb.append("Keccak[");
		sb.append(getBitrate());
		sb.append(", ");
		sb.append(getCapacity());
		sb.append("](M");
		if (getSuffixBits().isPresent()) {
			sb.append(" || ");
			sb.append(getSuffixBits().get());
			sb.append(',');
		} else {
			sb.append(',');
		}
		sb.append(' ');
		sb.append(getOutputLengthInBits());
		sb.append(')');
		return sb.toString();
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof KeccakSponge)) {
			return false;
		}
		KeccakSponge that = (KeccakSponge) obj;
		return this.bitrate == that.bitrate
				&& this.capacity == that.capacity
				&& this.outputLengthInBits == that.outputLengthInBits
				&& this.suffixBits.equals(that.suffixBits);
	}

	@Override
	public int hashCode() {
		int hash = 7;
		hash = 41 * hash + this.bitrate;
		hash = 41 * hash + this.capacity;
		hash = 41 * hash + Objects.hashCode(this.suffixBits);
		hash = 41 * hash + this.outputLengthInBits;
		return hash;
	}

	private static void validateBitrate(int bitrate) {
		if (bitrate < 1) {
			throw new IllegalArgumentException(
					"bitrate must be greater than zero.");
		}
		if (bitrate % Byte.SIZE != 0) {
			// TODO: Find KATs for Keccak with non-whole-byte bitrates, and add support to this library.
			throw new UnsupportedOperationException(
					"Currently only bitrates exactly divisible by 8 are supported.");
		}
		if (bitrate >= 1600) {
			throw new IllegalArgumentException(
					"bitrate must be less than 1600 bits.");
		}
	}

	private static void validateSuffixBits(String suffixBits) {
		Objects.requireNonNull(suffixBits);
		int length = suffixBits.length();
		for (int index = 0; index < length; ++index) {
			char c = suffixBits.charAt(index);
			if (c != '1' && c != '0') {
				throw new IllegalArgumentException(
						"If suffixBits is provided then it must be a bitstring. "
						+ "It can contain only digits 0 and 1 and nothing else.");
			}
		}
	}

	private static void validateCapacity(int capacity) {
		if (capacity < 1) {
			throw new IllegalArgumentException(
					"capacity must be greater than zero.");
		}
		if (capacity >= 1600) {
			throw new IllegalArgumentException(
					"capacity must be less than 1600 bits.");
		}
	}

	private static void validateOutputLength(int outputLength) {
		if (outputLength < 1) {
			throw new IllegalArgumentException(
					"outputLength must be greater than zero.");
		}
	}

	private static void validatePermutationWidth(short width) {
		// TODO: Add support for smaller widths (with lanes of less than one byte).
		// (Have not been able to find KATs for widths below 200 bits.)
		if (width < 200) {
			throw new UnsupportedOperationException(
					"Support is not yet in place for permutations widths smaller than 200 bits.");
		}
		if (!VALID_WIDTHS.contains(width)) {
			List<Short> validWidthList = new ArrayList<>(VALID_WIDTHS);
			validWidthList.sort((a, b) -> a - b);
			throw new IllegalArgumentException(
					"Sum of bitrate and capacity must equal a valid width: "
					+ validWidthList + ".");
		}
	}

	private static void validateMessageLength(byte[] message,
			int messageLengthInBits) {
		if (messageLengthInBits < 0) {
			throw new IllegalArgumentException(
					"messageLengthInBits cannot be negative.");
		}
		if (messageLengthInBits > message.length * Byte.SIZE) {
			throw new IllegalArgumentException(
					"messageLengthInBits cannot be greater than the bit length of the message byte array.");
		}
	}

	/**
	 * Copies the original message bits into the specified input array.
	 *
	 * @param message a byte array which represents the original message binary.
	 * @param messageLengthInBits the number of bits in the message byte array
	 * which actually form the message binary.
	 * @param input an empty byte array which is sufficiently large to take all
	 * of the message bits, any suffix bits, and the pad10*1 padding bits.
	 */
	private static void moveMessageBitsIntoInput(byte[] message,
			int messageLengthInBits, byte[] input) {
		assert message != null;
		assert messageLengthInBits >= 0;
		assert input != null;
		if (messageLengthInBits % Byte.SIZE == 0) {
			System.arraycopy(message, 0, input, 0, messageLengthInBits
					/ Byte.SIZE);
		} else {
			partialByteCopy(message, input, messageLengthInBits);
		}
	}

	/**
	 * Copies only the specified number of bits from the source array to the
	 * destination array.
	 *
	 * @param source the byte array to read bits from.
	 * @param destination the byte array to write bits into.
	 * @param bitLimit the exact number of bits to read from the source into the
	 * destination.
	 */
	private static void partialByteCopy(byte[] source, byte[] destination,
			int bitLimit) {
		assert source != null;
		assert destination != null;
		assert bitLimit >= 0;
		int wholeByteCount = bitLimit / Byte.SIZE;
		System.arraycopy(source, 0, destination, 0, wholeByteCount);
		int remainingBits = bitLimit % Byte.SIZE;
		for (int bitIndex = 0; bitIndex < remainingBits; ++bitIndex) {
			int bitValue = (1 << bitIndex);
			boolean sourceBitHigh = (source[wholeByteCount] & bitValue) != 0;
			if (sourceBitHigh) {
				destination[wholeByteCount] += bitValue;
			}
		}
	}

	private static void requireWholeByteBitrate(int bitrate) {
		assert bitrate > 0;
		if (bitrate % Byte.SIZE != 0) {
			throw new UnsupportedOperationException(
					"bitrate must be divisible by eight in order to process byte stream.");
		}
	}

	/**
	 * Returns a new byte array sufficiently large to hold the specified number
	 * of bits.
	 *
	 * @param bitCount the number of bits which needs to be wholly contained by
	 * the generated byte array.
	 * @return a byte array of sufficient size.
	 */
	private static byte[] createSufficientlyLargeByteArray(int bitCount) {
		assert bitCount > 0;
		int bytesRequired = divideThenRoundUp(bitCount, Byte.SIZE);
		return new byte[bytesRequired];
	}

	/*
	 * Java integer division rounds down any fractional remainder, but sometimes
	 * we need to divide integers and then round up any fractional remainder.
	 */
	private static int divideThenRoundUp(int dividend, int divisor) {
		assert dividend >= 0;
		assert divisor > 0;
		if (dividend == 0) {
			return 0;
		}
		if (dividend % divisor == 0) {
			return dividend / divisor;
		} else {
			return 1 + dividend / divisor;
		}
	}

	/*
	 * This main method is being used to run the profiler, so leave it in place
	 * until optimisation has been completed.
	 */
	public static void main(String[] args) {
		KeccakSponge spongeFunction = new KeccakSponge(576, 1024, "", 512);
		byte[] message = new byte[]{(byte) 19};
		byte[] hash = spongeFunction.apply(5, message);
		for (int i = 0; i < 900000; ++i) {
			hash = spongeFunction.apply(hash);
		}
	}
}
