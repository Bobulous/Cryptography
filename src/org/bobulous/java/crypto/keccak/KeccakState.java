/*
 * Copyright © 2017 Bobulous <http://www.bobulous.org.uk/>.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/.
 */
package uk.org.bobulous.java.crypto.keccak;

/**
 * The Keccak permutation state, which can absorb message input, be permuted,
 * and be squeezed to produce hash output. This object should not be shared and
 * should not be reused. It is intended solely to support a {@code KeccakSponge}
 * object.
 */
abstract class KeccakState {

	/**
	 * Set to {@code true} to enable the "The lane complementing transform"
	 * recommended by the "Keccak implementation overview" v3.2 (May 2012). Set
	 * to {@code false} to use the standard chi transform (which is expected to
	 * be more computationally expensive because it requires a greater number of
	 * bitwise NOT operations).
	 * <p>
	 * The "Keccak implementation overview" suggests that certain hardware
	 * architectures will run better with this feature disabled.</p>
	 */
	private static final boolean USE_BEBIGOKIMISA = true;

	abstract byte getLaneLengthInBits();

	abstract byte getNumberOfRoundsPerPermutation();

	/**
	 * Absorbs the given input into the Keccak state, reading blocks of at most
	 * {@code bitrate} bits at a time, and permuting the entire state after each
	 * block.
	 *
	 * @param input a byte array which contains the input bits. The input must
	 * already have been suffixed and padded before being provided to this
	 * method.
	 * @param inputLengthInBits the number of bits from the input byte array
	 * which should be considered part of the input, starting at the
	 * least-significant bit of the first byte in the array. This allows a byte
	 * array to represent a binary sequence with a length which is not exactly
	 * divisible by eight bits.
	 * @param bitrate the maximum number of bits to be read from the input in
	 * each block.
	 */
	void absorb(byte[] input, int inputLengthInBits, short bitrate) {
		assert input != null;
		assert inputLengthInBits >= 0;
		assert bitrate > 0;
		int inputBitIndex = 0;
		do {
			int readLength = Math.
					min(bitrate, inputLengthInBits - inputBitIndex);
			absorbBitsIntoState(input, inputBitIndex, readLength);
			permute();
			inputBitIndex += bitrate;
		} while (inputBitIndex < inputLengthInBits);
	}

	/**
	 * Absorbs into the Keccak state the specified portion of the given input.
	 *
	 * @param input a byte array which contains the input bits.
	 * @param inputStartBitIndex the index from which to start reading the input
	 * bits, where index zero is the least-significant bit of the first byte in
	 * the input array.
	 * @param readLengthInBits the exact number of bits to absorb from the input
	 * into the state.
	 */
	void absorbBitsIntoState(byte[] input, int inputStartBitIndex,
			int readLengthInBits) {
		byte laneLength = getLaneLengthInBits();
		assert input != null;
		assert inputStartBitIndex >= 0;
		assert readLengthInBits >= 0 && readLengthInBits <= laneLength * 25;
		int inputBitIndex = inputStartBitIndex;
		int readRemaining = readLengthInBits;
		for (int y = 0; y < 5; ++y) {
			for (int x = 0; x < 5; ++x) {
				if (inputBitIndex % Byte.SIZE == 0 && readRemaining
						>= laneLength) {
					absorbEntireLaneIntoState(input, inputBitIndex, x, y);
					inputBitIndex += laneLength;
					readRemaining -= laneLength;
				} else {
					absorbBitByBitIntoState(input, inputBitIndex, readRemaining,
							x, y);
					return;
				}
			}
		}
	}

	abstract void absorbEntireLaneIntoState(byte[] input, int inputBitIndex,
			int x, int y);

	abstract void absorbBitByBitIntoState(byte[] input, int inputStartBitIndex,
			int readLengthInBits, int x, int y);

	/**
	 * Applies the Keccak-F permutation function to this {@code KeccakState}.
	 */
	void permute() {
		if (USE_BEBIGOKIMISA) {
			applyComplementingPattern();
		}
		byte roundsPerPermutation = getNumberOfRoundsPerPermutation();
		for (int roundIndex = 0; roundIndex < roundsPerPermutation;
				++roundIndex) {
			permutationRound(roundIndex);
		}
		if (USE_BEBIGOKIMISA) {
			applyComplementingPattern();
		}
	}

	abstract void applyComplementingPattern();

	private void permutationRound(int roundIndex) {
		assert roundIndex >= 0 && roundIndex < getNumberOfRoundsPerPermutation();
		theta();
		rhoPi();
		if (USE_BEBIGOKIMISA) {
			chiWithLaneComplementingTransform();
		} else {
			chi();
		}
		iota(roundIndex);
	}

	abstract void theta();

	abstract void rhoPi();

	abstract void chi();

	abstract void chiWithLaneComplementingTransform();

	abstract void iota(int roundIndex);

	/**
	 * Squeezes the Keccak sponge state as many times as needed to generate and
	 * return output of the requested length.
	 * <p>
	 * If the output length is a number of bits which does not divide exactly by
	 * eight then be aware that the most-significant bits of the final byte of
	 * the returned array must not be considered part of the hash result. For
	 * example, if output length of 12 is requested then the returned array will
	 * be two bytes in length, and all of the bits of the first byte will be
	 * part of the hash result, but only the least-significant four bits of the
	 * second byte will be part of the hash result.</p>
	 *
	 * @param bitrate the maximum number of bits to squeeze out of the state in
	 * each block before the state is permuted.
	 * @param outputLengthInBits the required output size, in bits.
	 * @return a byte array which represents the output squeezed from the Keccak
	 * permutation state.
	 */
	byte[] squeeze(short bitrate, int outputLengthInBits) {
		assert bitrate > 0;
		assert outputLengthInBits > 0;
		byte[] output = createOutputArray(outputLengthInBits);
		int writeLength = Math.min(bitrate, outputLengthInBits);
		squeezeBitsFromState(output, 0, writeLength);
		for (int outputBitIndex = bitrate; outputBitIndex < outputLengthInBits;
				outputBitIndex += bitrate) {
			permute();
			writeLength = Math.min(bitrate, outputLengthInBits - outputBitIndex);
			squeezeBitsFromState(output, outputBitIndex, writeLength);
		}
		return output;
	}

	private byte[] createOutputArray(int outputLengthInBits) {
		assert outputLengthInBits > 0;
		int requiredBytes = outputLengthInBits / Byte.SIZE;
		if (outputLengthInBits % Byte.SIZE != 0) {
			++requiredBytes;
		}
		return new byte[requiredBytes];
	}

	private void squeezeBitsFromState(byte[] output, int outputStartBitIndex,
			int writeLength) {
		byte laneLength = getLaneLengthInBits();
		assert output != null;
		assert outputStartBitIndex >= 0;
		assert writeLength >= 0;
		// TODO: Adapt this method for lanes of length 1, 2, and 4 bits once KATs are found.
		assert laneLength >= Byte.SIZE;
		int outputBitIndex = outputStartBitIndex;
		int outputStopIndex = outputStartBitIndex + writeLength;
		for (int y = 0; y < 5; ++y) {
			for (int x = 0; x < 5; ++x) {
				if (outputBitIndex == outputStopIndex) {
					return;
				}
				if (outputBitIndex % Byte.SIZE == 0 && writeLength
						- outputBitIndex
						>= laneLength) {
					squeezeEntireLaneIntoOutput(x, y, output, outputBitIndex);
					outputBitIndex += laneLength;
				} else {
					outputBitIndex = squeezeLaneBitByBitIntoOutput(output,
							outputBitIndex, outputStopIndex, x, y);
				}
			}
		}
	}

	abstract void squeezeEntireLaneIntoOutput(int x, int y, byte[] output,
			int outputBitIndex);

	abstract int squeezeLaneBitByBitIntoOutput(byte[] output, int outputBitIndex,
			int outputStopIndex, int x, int y);

	@Override
	public final boolean equals(Object obj) {
		throw new AssertionError(
				"The equals method of KeccakState is not intended for use.");
	}

	@Override
	public final int hashCode() {
		throw new AssertionError(
				"The hashCode method of KeccakState is not intended for use.");
	}

	/**
	 * Reports on the state of the bit within the given byte array at the given
	 * array-wide bit index.
	 * <p>
	 * For example, if the given byte array is two bytes in length and the
	 * specified bit index is 9 then this method will report on the state of the
	 * least-significant bit of the second byte.
	 * </p>
	 *
	 * @param input a byte array. Must not be null.
	 * @param inputBitIndex the array-wide index of the bit of interest.
	 * @return {@code true} if the specified bit is high (binary "1");
	 * {@code false} if the specified bit is low (binary "0").
	 */
	protected static boolean isInputBitHigh(byte[] input, int inputBitIndex) {
		assert input != null;
		assert inputBitIndex >= 0 && inputBitIndex < input.length * Byte.SIZE;
		int inputByteIndex = inputBitIndex / Byte.SIZE;
		int inputByteBitIndex = inputBitIndex % Byte.SIZE;
		return 0 != (input[inputByteIndex] & (1 << inputByteBitIndex));
	}

	/**
	 * Modifies the given byte array to set to high the state of the specified
	 * array-wide bit index.
	 * <p>
	 * For example, if the given byte array is three bytes in length and the
	 * specified bit index is 16 then this method will modify the
	 * least-significant bit of the third byte. The bit will be set high (binary
	 * "1").</p>
	 * <p>
	 * <strong>Important:</strong> this method assumes that the specified bit is
	 * initially low (binary "0"). This method must not be called to operate on
	 * a bit which is not guaranteed to start out with a low setting.</p>
	 *
	 * @param output a byte array being used to hold the output squeezed from a
	 * Keccak sponge.
	 * @param outputBitIndex the array-wide index of the bit to modify.
	 */
	protected static void setOutputBitHigh(byte[] output, int outputBitIndex) {
		assert output != null;
		assert outputBitIndex >= 0;
		int outputByteIndex = outputBitIndex / Byte.SIZE;
		byte outputByteBitIndex = (byte) (outputBitIndex % Byte.SIZE);
		byte byteBitValue = (byte) (1 << outputByteBitIndex);
		output[outputByteIndex] += byteBitValue;
	}
}
