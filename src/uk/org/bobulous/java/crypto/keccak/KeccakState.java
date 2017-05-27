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
final class KeccakState {

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

	/*
	 * The Keccak permutation state, represented by a 5x5 array of "lanes".
	 */
	private final long[][] laneArray = new long[5][5];

	/*
	 * The length in bits of each "lane" within the Keccak permutation state
	 * array.
	 */
	private final byte laneLength;

	/*
	 * A mask of high bits indicating the full length of a lane. This is used in
	 * cases where the Keccak lane length is less than 64 bits, to allow a Java
	 * 64-bit long primitive to be used to represent each lane without the
	 * higher bit indices being taken into consideration during inversion and
	 * rotation actions.
	 */
	private final long laneMask;

	private final int numberOfRoundsPerPermutation;
	private final long[] roundConstants;
	private final byte[][] rotationConstants;

	/*
	 * Used by the rhoPiChi() method. Every member of this array is overwritten
	 * before any member is read (within each permutation round) so it's safe to
	 * create a single multi-dimensional array here and use it over and over
	 * again.
	 */
	private final long[][] b = new long[5][5];

	/*
	 * Used by the theta() method. Every member of each array is overwritten
	 * before any member is read (within each permutation round) so it's safe to
	 * create a single multi-dimensional array for each and use them repeatedly.
	 */
	private final long[] c = new long[5];
	private final long[] d = new long[5];

	/**
	 * Constructs a new {@code KeccakSponge} with the given parameters. Objects
	 * of this type are mutable and intended for single-use only. Do not share
	 * or reuse {@code KeccakSponge} objects.
	 * <p>
	 * All of the parameters passed to this constructor should have been set or
	 * calculated in a {@code KeccakSponge} object which creates this
	 * {@code KeccakState} object for the purpose of calculating a hash result.
	 * </p>
	 *
	 * @param laneLength the length, in bits, of each lane within the state.
	 * @param roundsPerPermutation the number of times to repeat the theta, rho,
	 * pi, chi, iota round sequence each time the state is permuted.
	 * @param roundConstants a long array which contains the Keccak round
	 * constants which must be applied for each Keccak permutation round.
	 * @param rotationConstants a two-dimensional byte array which contains the
	 * Keccak rotation constants which apply to each of the twenty-five lanes
	 * found in the two-dimensional lane array.
	 */
	KeccakState(byte laneLength, int roundsPerPermutation,
			long[] roundConstants, byte[][] rotationConstants) {
		assert laneLength >= 0 && laneLength <= 64;
		assert roundsPerPermutation >= 12 && roundsPerPermutation <= 24;
		assert roundConstants != null;
		assert rotationConstants != null;
		this.laneLength = laneLength;
		this.numberOfRoundsPerPermutation = roundsPerPermutation;
		initialiseLaneArray();
		this.roundConstants = roundConstants;
		this.rotationConstants = rotationConstants;
		this.laneMask = ((1L << laneLength) - 1);
	}

	private void initialiseLaneArray() {
		for (int x = 0; x < 5; ++x) {
			for (int y = 0; y < 5; ++y) {
				laneArray[x][y] = 0L;
			}
		}
	}

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
		assert input != null;
		assert inputStartBitIndex >= 0;
		assert readLengthInBits >= 0 && readLengthInBits <= laneLength * 25;
		int inputBitIndex = inputStartBitIndex;
		int readRemaining = readLengthInBits;
		for (int y = 0; y < 5; ++y) {
			for (int x = 0; x < 5; ++x) {
				if (inputBitIndex % 8 == 0 && readRemaining >= laneLength) {
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

	private void absorbEntireLaneIntoState(byte[] input, int inputBitIndex,
			int x, int y) {
		assert laneLength >= 8;
		assert input != null;
		assert inputBitIndex % 8 == 0;
		assert x >= 0 && x < 5;
		assert x >= 0 && y < 5;
		int laneByteCount = laneLength / 8;
		int inputByteStartIndex = inputBitIndex / 8;
		long laneValue = 0L;
		for (int laneByteIndex = laneByteCount - 1; laneByteIndex >= 0;
				--laneByteIndex) {
			laneValue <<= 8;
			laneValue += Byte.toUnsignedInt(input[inputByteStartIndex
					+ laneByteIndex]);
		}
		laneArray[x][y] = laneArray[x][y] ^ laneValue;
	}

	private void absorbBitByBitIntoState(byte[] input, int inputStartBitIndex,
			int readLengthInBits, int x, int y) {
		assert input != null;
		assert inputStartBitIndex >= 0;
		assert readLengthInBits >= 0;
		assert x >= 0 && x < 5;
		assert y >= 0 && y < 5;
		int inputStopBitIndex = inputStartBitIndex + readLengthInBits;
		int z = 0;
		for (int inputBitIndex = inputStartBitIndex; inputBitIndex
				< inputStopBitIndex; ++inputBitIndex) {
			assert y < 5;
			if (inputBitIsHigh(input, inputBitIndex)) {
				laneArray[x][y] = laneArray[x][y] ^ (1L << z);
			}
			if (++z == laneLength) {
				++x;
				z = 0;
			}
			if (x == 5) {
				++y;
				x = 0;
			}
		}
	}

	private boolean inputBitIsHigh(byte[] input, int inputBitIndex) {
		assert input != null;
		assert inputBitIndex >= 0;
		int inputByteIndex = inputBitIndex / 8;
		int inputByteBitIndex = inputBitIndex % 8;
		return 0 != (input[inputByteIndex] & (1 << inputByteBitIndex));
	}

	/**
	 * Applies the Keccak-F permutation function to this {@code KeccakState}.
	 */
	void permute() {
		if (USE_BEBIGOKIMISA) {
			applyComplementingPattern();
		}
		for (int roundIndex = 0; roundIndex < numberOfRoundsPerPermutation;
				++roundIndex) {
			permutationRound(roundIndex);
		}
		if (USE_BEBIGOKIMISA) {
			applyComplementingPattern();
		}
	}

	/*
	 * Based on the technique described in "The lane complementing transform" in
	 * the "Keccak implementation overview" v3.2 (May 2012). Be aware that when
	 * this complementing pattern is used, it will not make sense to use a
	 * logger to write the state to the console, because the lane complementing
	 * transform will mean that the state snapshots will not resemble those seen
	 * in the "intermediate" steps of KAT documents.
	 */
	private void applyComplementingPattern() {
		laneArray[1][0] = not(laneArray[1][0]);
		laneArray[2][0] = not(laneArray[2][0]);
		laneArray[3][1] = not(laneArray[3][1]);
		laneArray[2][2] = not(laneArray[2][2]);
		laneArray[2][3] = not(laneArray[2][3]);
		laneArray[0][4] = not(laneArray[0][4]);
	}

	private void permutationRound(int roundIndex) {
		assert roundIndex >= 0 && roundIndex < numberOfRoundsPerPermutation;
		theta();
		rhoPi();
		if (USE_BEBIGOKIMISA) {
			chiWithLaneComplementingTransform();
		} else {
			chi();
		}
		iota(roundIndex);
	}

	private void theta() {
		thetaC();
		thetaD();
		for (int y = 0; y < 5; ++y) {
			for (int x = 0; x < 5; ++x) {
				laneArray[x][y] = laneArray[x][y] ^ d[x];
			}
		}
	}

	private void thetaC() {
		for (int x = 0; x < 5; ++x) {
			c[x] = laneArray[x][0] ^ laneArray[x][1] ^ laneArray[x][2]
					^ laneArray[x][3] ^ laneArray[x][4];
		}
	}

	private void thetaD() {
		d[0] = c[4] ^ rot(c[1], 1);
		d[1] = c[0] ^ rot(c[2], 1);
		d[2] = c[1] ^ rot(c[3], 1);
		d[3] = c[2] ^ rot(c[4], 1);
		d[4] = c[3] ^ rot(c[0], 1);
	}

	private long rot(long lane, int rotateBy) {
		assert rotateBy >= 0 && rotateBy < laneLength;
		switch (laneLength) {
			case 64:
				return Long.rotateLeft(lane, rotateBy);
			default:
				return smallLaneRotation(lane, rotateBy);
		}
	}

	private long smallLaneRotation(long lane, int rotateBy) {
		assert rotateBy >= 0 && rotateBy < laneLength;
		long result = (lane << rotateBy) | (lane >>> (laneLength - rotateBy));
		result = result & laneMask;
		return result;
	}

	private void rhoPi() {
		for (int x = 0; x < 5; ++x) {
			for (int y = 0; y < 5; ++y) {
				b[y][(2 * x + 3 * y) % 5] = rot(laneArray[x][y],
						rotationConstants[x][y]);
			}
		}
	}

	private void chi() {
		for (int y = 0; y < 5; ++y) {
			laneArray[0][y] = b[0][y] ^ (not(b[1][y]) & b[2][y]);
			laneArray[1][y] = b[1][y] ^ (not(b[2][y]) & b[3][y]);
			laneArray[2][y] = b[2][y] ^ (not(b[3][y]) & b[4][y]);
			laneArray[3][y] = b[3][y] ^ (not(b[4][y]) & b[0][y]);
			laneArray[4][y] = b[4][y] ^ (not(b[0][y]) & b[1][y]);
		}
	}

	/*
	 * Based on the technique described in "The lane complementing transform" in
	 * the "Keccak implementation overview" v3.2 (May 2012). The permutation
	 * sequencing was copied from the file KeccakF-1600-64.macros (in the
	 * KeccakReferenceAndOptimized package created by the Keccak team).
	 * Specifically the branch `#ifdef UseBebigokimisa` and `#define
	 * thetaRhoPiChiIota(i, A, E)`.
	 */
	private void chiWithLaneComplementingTransform() {
		laneArray[0][0] = b[0][0] ^ (b[1][0] | b[2][0]);
		laneArray[1][0] = b[1][0] ^ (not(b[2][0]) | b[3][0]);
		laneArray[2][0] = b[2][0] ^ (b[3][0] & b[4][0]);
		laneArray[3][0] = b[3][0] ^ (b[4][0] | b[0][0]);
		laneArray[4][0] = b[4][0] ^ (b[0][0] & b[1][0]);

		laneArray[0][1] = b[0][1] ^ (b[1][1] | b[2][1]);
		laneArray[1][1] = b[1][1] ^ (b[2][1] & b[3][1]);
		laneArray[2][1] = b[2][1] ^ (b[3][1] | not(b[4][1]));
		laneArray[3][1] = b[3][1] ^ (b[4][1] | b[0][1]);
		laneArray[4][1] = b[4][1] ^ (b[0][1] & b[1][1]);

		long invertedLaneThreeTwo = not(b[3][2]);
		laneArray[0][2] = b[0][2] ^ (b[1][2] | b[2][2]);
		laneArray[1][2] = b[1][2] ^ (b[2][2] & b[3][2]);
		laneArray[2][2] = b[2][2] ^ (invertedLaneThreeTwo & b[4][2]);
		laneArray[3][2] = invertedLaneThreeTwo ^ (b[4][2] | b[0][2]);
		laneArray[4][2] = b[4][2] ^ (b[0][2] & b[1][2]);

		long invertedLaneThreeThree = not(b[3][3]);
		laneArray[0][3] = b[0][3] ^ (b[1][3] & b[2][3]);
		laneArray[1][3] = b[1][3] ^ (b[2][3] | b[3][3]);
		laneArray[2][3] = b[2][3] ^ (invertedLaneThreeThree | b[4][3]);
		laneArray[3][3] = invertedLaneThreeThree ^ (b[4][3] & b[0][3]);
		laneArray[4][3] = b[4][3] ^ (b[0][3] | b[1][3]);

		long invertedLaneOneFour = not(b[1][4]);
		laneArray[0][4] = b[0][4] ^ (invertedLaneOneFour & b[2][4]);
		laneArray[1][4] = invertedLaneOneFour ^ (b[2][4] | b[3][4]);
		laneArray[2][4] = b[2][4] ^ (b[3][4] & b[4][4]);
		laneArray[3][4] = b[3][4] ^ (b[4][4] | b[0][4]);
		laneArray[4][4] = b[4][4] ^ (b[0][4] & b[1][4]);
	}

	private long not(long lane) {
		switch (laneLength) {
			case 64:
				return ~lane;
			default:
				return smallLaneInversion(lane);
		}
	}

	private long smallLaneInversion(long lane) {
		long inverted = lane ^ laneMask;
		return inverted;
	}

	private void iota(int roundIndex) {
		assert roundIndex >= 0 && roundIndex < numberOfRoundsPerPermutation;
		laneArray[0][0] = laneArray[0][0] ^ roundConstants[roundIndex];
	}

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
		int requiredBytes = outputLengthInBits / 8;
		if (outputLengthInBits % 8 != 0) {
			++requiredBytes;
		}
		return new byte[requiredBytes];
	}

	private void squeezeBitsFromState(byte[] output, int outputStartBitIndex,
			int writeLength) {
		assert output != null;
		assert outputStartBitIndex >= 0;
		assert writeLength >= 0;
		// TODO: Adapt this method for lanes of length 1, 2, and 4 bits once KATs are found.
		assert laneLength >= 8;
		int outputBitIndex = outputStartBitIndex;
		int outputStopIndex = outputStartBitIndex + writeLength;
		for (int y = 0; y < 5; ++y) {
			for (int x = 0; x < 5; ++x) {
				if (outputBitIndex == outputStopIndex) {
					return;
				}
				if (outputBitIndex % 8 == 0 && writeLength - outputBitIndex
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

	private void squeezeEntireLaneIntoOutput(int x, int y, byte[] output,
			int outputBitIndex) {
		assert x >= 0 && x < 5;
		assert y >= 0 && y < 5;
		assert output != null;
		assert outputBitIndex >= 0;
		long laneValue = laneArray[x][y];
		int laneByteCount = laneLength / 8;
		int finalLaneByteIndex = laneByteCount - 1;
		int outputByteIndex = outputBitIndex / 8;
		for (int laneByteIndex = finalLaneByteIndex; laneByteIndex >= 0;
				--laneByteIndex) {
			byte laneChunk = (byte) (laneValue & 0xff);
			output[outputByteIndex + (finalLaneByteIndex - laneByteIndex)]
					= laneChunk;
			laneValue >>= 8;
		}
	}

	private int squeezeLaneBitByBitIntoOutput(byte[] output, int outputBitIndex,
			int outputStopIndex, int x, int y) {
		assert output != null;
		assert outputBitIndex >= 0;
		assert x >= 0 && x < 5;
		assert y >= 0 && y < 5;
		for (int z = 0; z < laneLength; ++z) {
			if (outputBitIndex == outputStopIndex) {
				break;
			}
			boolean bitHigh = (laneArray[x][y] & (1L << z)) != 0;
			if (bitHigh) {
				setOutputBitHigh(output, outputBitIndex);
			}
			++outputBitIndex;
		}
		return outputBitIndex;
	}

	private void setOutputBitHigh(byte[] output, int outputBitIndex) {
		assert output != null;
		assert outputBitIndex >= 0;
		int outputByteIndex = outputBitIndex / 8;
		byte outputByteBitIndex = (byte) (outputBitIndex % 8);
		byte byteBitValue = (byte) (1 << outputByteBitIndex);
		output[outputByteIndex] += byteBitValue;
	}

	@Override
	public boolean equals(Object obj) {
		throw new AssertionError(
				"The equals method of KeccakState is not intended for use.");
	}

	@Override
	public int hashCode() {
		throw new AssertionError(
				"The hashCode method of KeccakState is not intended for use.");
	}
}
