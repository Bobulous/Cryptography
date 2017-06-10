/*
 * Copyright © 2017 Bobulous <http://www.bobulous.org.uk/>.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/.
 */
package uk.org.bobulous.java.crypto.keccak;

/**
 * A KeccakState with permutation width of 1600 bits and lane length of 64 bits.
 * <p>
 * The logic used within most of the methods in this class is identical to that
 * used in the KeccakState classes for other permutation widths. But because the
 * state array has a different type ({@code long} in this case) and because the
 * bitwise operations have to be written for each specific lane width, each
 * width does need its own version of most methods.</p>
 */
final class KeccakState1600 extends KeccakState {

	/*
	 * The Keccak permutation state, represented by a 5x5 array of "lanes". For
	 * this width 1600 state, where each lane is 64 bits in length, we'll
	 * represent each lane with a Java long primitive (64 bits).
	 */
	private final long[][] laneArray = new long[5][5];

	private static final byte LANE_LENGTH = 64;

	private static final byte NUMBER_OF_ROUNDS_PER_PERMUTATION = 24;

	private static final long[] ROUND_CONSTANTS_FOR_WIDTH_1600;

	static {
		ROUND_CONSTANTS_FOR_WIDTH_1600 = new long[]{
			1L,
			32898L,
			-9223372036854742902L,
			-9223372034707259392L,
			32907L,
			2147483649L,
			-9223372034707259263L,
			-9223372036854743031L,
			138L,
			136L,
			2147516425L,
			2147483658L,
			2147516555L,
			-9223372036854775669L,
			-9223372036854742903L,
			-9223372036854743037L,
			-9223372036854743038L,
			-9223372036854775680L,
			32778L,
			-9223372034707292150L,
			-9223372034707259263L,
			-9223372036854742912L,
			2147483649L,
			-9223372034707259384L
		};
	}

	private static final byte[][] ROTATION_CONSTANTS_FOR_WIDTH_1600;

	static {
		byte[][] rotOffsets = new byte[5][5];
		rotOffsets[0] = new byte[]{
			(byte) 0,
			(byte) 36,
			(byte) 3,
			(byte) 41,
			(byte) 18};
		rotOffsets[1] = new byte[]{
			(byte) 1,
			(byte) 44,
			(byte) 10,
			(byte) 45,
			(byte) 2};
		rotOffsets[2] = new byte[]{
			(byte) 62,
			(byte) 6,
			(byte) 43,
			(byte) 15,
			(byte) 61};
		rotOffsets[3] = new byte[]{
			(byte) 28,
			(byte) 55,
			(byte) 25,
			(byte) 21,
			(byte) 56};
		rotOffsets[4] = new byte[]{
			(byte) 27,
			(byte) 20,
			(byte) 39,
			(byte) 8,
			(byte) 14
		};
		ROTATION_CONSTANTS_FOR_WIDTH_1600 = rotOffsets;
	}

	/*
	 * Used by the rhoPi() method. Every member of this array is overwritten
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

	@Override
	byte getLaneLengthInBits() {
		return LANE_LENGTH;
	}

	@Override
	byte getNumberOfRoundsPerPermutation() {
		return NUMBER_OF_ROUNDS_PER_PERMUTATION;
	}

	public KeccakState1600() {
		initialiseLaneArray();
	}

	private void initialiseLaneArray() {
		for (int x = 0; x < 5; ++x) {
			for (int y = 0; y < 5; ++y) {
				laneArray[x][y] = 0L;
			}
		}
	}

	@Override
	void absorbEntireLaneIntoState(byte[] input, int inputBitIndex, int x, int y) {
		assert input != null;
		assert inputBitIndex % Byte.SIZE == 0;
		assert x >= 0 && x < 5;
		assert x >= 0 && y < 5;
		int laneByteCount = LANE_LENGTH / Byte.SIZE;
		int inputByteStartIndex = inputBitIndex / Byte.SIZE;
		long laneValue = 0L;
		for (int laneByteIndex = laneByteCount - 1; laneByteIndex >= 0;
				--laneByteIndex) {
			laneValue <<= Byte.SIZE;
			laneValue += Byte.toUnsignedInt(input[inputByteStartIndex
					+ laneByteIndex]);
		}
		laneArray[x][y] = laneArray[x][y] ^ laneValue;
	}

	@Override
	void absorbBitByBitIntoState(byte[] input, int inputStartBitIndex,
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
			if (isInputBitHigh(input, inputBitIndex)) {
				laneArray[x][y] = laneArray[x][y] ^ (1L << z);
			}
			if (++z == LANE_LENGTH) {
				++x;
				z = 0;
			}
			if (x == 5) {
				++y;
				x = 0;
			}
		}
	}

	@Override
	void applyComplementingPattern() {
		laneArray[1][0] = ~laneArray[1][0];
		laneArray[2][0] = ~laneArray[2][0];
		laneArray[3][1] = ~laneArray[3][1];
		laneArray[2][2] = ~laneArray[2][2];
		laneArray[2][3] = ~laneArray[2][3];
		laneArray[0][4] = ~laneArray[0][4];
	}

	@Override
	void theta() {
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
		d[0] = c[4] ^ Long.rotateLeft(c[1], 1);
		d[1] = c[0] ^ Long.rotateLeft(c[2], 1);
		d[2] = c[1] ^ Long.rotateLeft(c[3], 1);
		d[3] = c[2] ^ Long.rotateLeft(c[4], 1);
		d[4] = c[3] ^ Long.rotateLeft(c[0], 1);
	}

	@Override
	void rhoPi() {
		b[0][0] = Long.rotateLeft(laneArray[0][0],
				ROTATION_CONSTANTS_FOR_WIDTH_1600[0][0]);
		b[1][3] = Long.rotateLeft(laneArray[0][1],
				ROTATION_CONSTANTS_FOR_WIDTH_1600[0][1]);
		b[2][1] = Long.rotateLeft(laneArray[0][2],
				ROTATION_CONSTANTS_FOR_WIDTH_1600[0][2]);
		b[3][4] = Long.rotateLeft(laneArray[0][3],
				ROTATION_CONSTANTS_FOR_WIDTH_1600[0][3]);
		b[4][2] = Long.rotateLeft(laneArray[0][4],
				ROTATION_CONSTANTS_FOR_WIDTH_1600[0][4]);

		b[0][2] = Long.rotateLeft(laneArray[1][0],
				ROTATION_CONSTANTS_FOR_WIDTH_1600[1][0]);
		b[1][0] = Long.rotateLeft(laneArray[1][1],
				ROTATION_CONSTANTS_FOR_WIDTH_1600[1][1]);
		b[2][3] = Long.rotateLeft(laneArray[1][2],
				ROTATION_CONSTANTS_FOR_WIDTH_1600[1][2]);
		b[3][1] = Long.rotateLeft(laneArray[1][3],
				ROTATION_CONSTANTS_FOR_WIDTH_1600[1][3]);
		b[4][4] = Long.rotateLeft(laneArray[1][4],
				ROTATION_CONSTANTS_FOR_WIDTH_1600[1][4]);

		b[0][4] = Long.rotateLeft(laneArray[2][0],
				ROTATION_CONSTANTS_FOR_WIDTH_1600[2][0]);
		b[1][2] = Long.rotateLeft(laneArray[2][1],
				ROTATION_CONSTANTS_FOR_WIDTH_1600[2][1]);
		b[2][0] = Long.rotateLeft(laneArray[2][2],
				ROTATION_CONSTANTS_FOR_WIDTH_1600[2][2]);
		b[3][3] = Long.rotateLeft(laneArray[2][3],
				ROTATION_CONSTANTS_FOR_WIDTH_1600[2][3]);
		b[4][1] = Long.rotateLeft(laneArray[2][4],
				ROTATION_CONSTANTS_FOR_WIDTH_1600[2][4]);

		b[0][1] = Long.rotateLeft(laneArray[3][0],
				ROTATION_CONSTANTS_FOR_WIDTH_1600[3][0]);
		b[1][4] = Long.rotateLeft(laneArray[3][1],
				ROTATION_CONSTANTS_FOR_WIDTH_1600[3][1]);
		b[2][2] = Long.rotateLeft(laneArray[3][2],
				ROTATION_CONSTANTS_FOR_WIDTH_1600[3][2]);
		b[3][0] = Long.rotateLeft(laneArray[3][3],
				ROTATION_CONSTANTS_FOR_WIDTH_1600[3][3]);
		b[4][3] = Long.rotateLeft(laneArray[3][4],
				ROTATION_CONSTANTS_FOR_WIDTH_1600[3][4]);

		b[0][3] = Long.rotateLeft(laneArray[4][0],
				ROTATION_CONSTANTS_FOR_WIDTH_1600[4][0]);
		b[1][1] = Long.rotateLeft(laneArray[4][1],
				ROTATION_CONSTANTS_FOR_WIDTH_1600[4][1]);
		b[2][4] = Long.rotateLeft(laneArray[4][2],
				ROTATION_CONSTANTS_FOR_WIDTH_1600[4][2]);
		b[3][2] = Long.rotateLeft(laneArray[4][3],
				ROTATION_CONSTANTS_FOR_WIDTH_1600[4][3]);
		b[4][0] = Long.rotateLeft(laneArray[4][4],
				ROTATION_CONSTANTS_FOR_WIDTH_1600[4][4]);
	}

	@Override
	void chi() {
		for (int y = 0; y < 5; ++y) {
			laneArray[0][y] = b[0][y] ^ (~b[1][y] & b[2][y]);
			laneArray[1][y] = b[1][y] ^ (~b[2][y] & b[3][y]);
			laneArray[2][y] = b[2][y] ^ (~b[3][y] & b[4][y]);
			laneArray[3][y] = b[3][y] ^ (~b[4][y] & b[0][y]);
			laneArray[4][y] = b[4][y] ^ (~b[0][y] & b[1][y]);
		}
	}

	@Override
	void chiWithLaneComplementingTransform() {
		long invertedLaneTwoZero = ~b[2][0];
		laneArray[0][0] = b[0][0] ^ (b[1][0] | b[2][0]);
		laneArray[1][0] = b[1][0] ^ (invertedLaneTwoZero | b[3][0]);
		laneArray[2][0] = b[2][0] ^ (b[3][0] & b[4][0]);
		laneArray[3][0] = b[3][0] ^ (b[4][0] | b[0][0]);
		laneArray[4][0] = b[4][0] ^ (b[0][0] & b[1][0]);

		long invertedLaneFourOne = ~b[4][1];
		laneArray[0][1] = b[0][1] ^ (b[1][1] | b[2][1]);
		laneArray[1][1] = b[1][1] ^ (b[2][1] & b[3][1]);
		laneArray[2][1] = b[2][1] ^ (b[3][1] | invertedLaneFourOne);
		laneArray[3][1] = b[3][1] ^ (b[4][1] | b[0][1]);
		laneArray[4][1] = b[4][1] ^ (b[0][1] & b[1][1]);

		long invertedLaneThreeTwo = ~b[3][2];
		laneArray[0][2] = b[0][2] ^ (b[1][2] | b[2][2]);
		laneArray[1][2] = b[1][2] ^ (b[2][2] & b[3][2]);
		laneArray[2][2] = b[2][2] ^ (invertedLaneThreeTwo & b[4][2]);
		laneArray[3][2] = invertedLaneThreeTwo ^ (b[4][2] | b[0][2]);
		laneArray[4][2] = b[4][2] ^ (b[0][2] & b[1][2]);

		long invertedLaneThreeThree = ~b[3][3];
		laneArray[0][3] = b[0][3] ^ (b[1][3] & b[2][3]);
		laneArray[1][3] = b[1][3] ^ (b[2][3] | b[3][3]);
		laneArray[2][3] = b[2][3] ^ (invertedLaneThreeThree | b[4][3]);
		laneArray[3][3] = invertedLaneThreeThree ^ (b[4][3] & b[0][3]);
		laneArray[4][3] = b[4][3] ^ (b[0][3] | b[1][3]);

		long invertedLaneOneFour = ~b[1][4];
		laneArray[0][4] = b[0][4] ^ (invertedLaneOneFour & b[2][4]);
		laneArray[1][4] = invertedLaneOneFour ^ (b[2][4] | b[3][4]);
		laneArray[2][4] = b[2][4] ^ (b[3][4] & b[4][4]);
		laneArray[3][4] = b[3][4] ^ (b[4][4] | b[0][4]);
		laneArray[4][4] = b[4][4] ^ (b[0][4] & b[1][4]);
	}

	@Override
	void iota(int roundIndex) {
		assert roundIndex >= 0 && roundIndex < NUMBER_OF_ROUNDS_PER_PERMUTATION;
		laneArray[0][0] = laneArray[0][0]
				^ ROUND_CONSTANTS_FOR_WIDTH_1600[roundIndex];
	}

	@Override
	void squeezeEntireLaneIntoOutput(int x, int y, byte[] output,
			int outputBitIndex) {
		assert x >= 0 && x < 5;
		assert y >= 0 && y < 5;
		assert output != null;
		assert outputBitIndex >= 0;
		long laneValue = laneArray[x][y];
		int laneByteCount = LANE_LENGTH / Byte.SIZE;
		int finalLaneByteIndex = laneByteCount - 1;
		int outputByteIndex = outputBitIndex / Byte.SIZE;
		for (int laneByteIndex = finalLaneByteIndex; laneByteIndex >= 0;
				--laneByteIndex) {
			byte laneChunk = (byte) (laneValue & 0xff);
			output[outputByteIndex + (finalLaneByteIndex - laneByteIndex)]
					= laneChunk;
			laneValue >>= Byte.SIZE;
		}
	}

	@Override
	int squeezeLaneBitByBitIntoOutput(byte[] output, int outputBitIndex,
			int outputStopIndex, int x, int y) {
		assert output != null;
		assert outputBitIndex >= 0;
		assert x >= 0 && x < 5;
		assert y >= 0 && y < 5;
		for (int z = 0; z < LANE_LENGTH; ++z) {
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
}
