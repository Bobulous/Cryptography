/*
 * Copyright © 2017 Bobulous <http://www.bobulous.org.uk/>.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/.
 */
package uk.org.bobulous.java.crypto.keccak;

/**
 * A KeccakState with permutation width of at most 400 bits and lane length of
 * less than 32 bits, but which is represented by a lane array of Java
 * {@code int} primitive.
 * <p>
 * Given that the lane length is less than 32 bits, it's tempting to use a Java
 * {@code short} or {@code byte} primitive for each lane as appropriate.
 * However, Java promotes all shorter values to an {@code int} while operating
 * on them, so it's probably less efficient to use the shorter primitive types.
 * Instead, these shorter permutation widths will use a lane array of
 * {@code int} values, and then use a lane mask which focuses only on the
 * least-significant bits within each {@code int} which represent the actual
 * data of the shorter lane.
 * </p>
 */
abstract class KeccakShortState extends KeccakState {

	/*
	 * The Keccak permutation state, represented by a 5x5 array of "lanes".
	 */
	protected final int[][] laneArray = new int[5][5];

	/*
	 * Used by the rhoPi() method. Every member of this array is overwritten
	 * before any member is read (within each permutation round) so it's safe to
	 * create a single multi-dimensional array here and use it over and over
	 * again.
	 */
	protected final int[][] b = new int[5][5];

	/*
	 * Used by the theta() method. Every member of each array is overwritten
	 * before any member is read (within each permutation round) so it's safe to
	 * create a single multi-dimensional array for each and use them repeatedly.
	 */
	protected final int[] c = new int[5];
	protected final int[] d = new int[5];

	@Override
	abstract byte getLaneLengthInBits();

	@Override
	abstract byte getNumberOfRoundsPerPermutation();

	abstract int getLaneMask();

	abstract byte getRotationConstantForLane(int x, int y);

	abstract int getRoundConstantForRound(int roundIndex);

	public KeccakShortState() {
		initialiseLaneArray();
	}

	private void initialiseLaneArray() {
		for (int x = 0; x < 5; ++x) {
			for (int y = 0; y < 5; ++y) {
				laneArray[x][y] = 0;
			}
		}
	}

	@Override
	void absorbEntireLaneIntoState(byte[] input, int inputBitIndex, int x, int y) {
		assert input != null;
		assert inputBitIndex % Byte.SIZE == 0;
		assert x >= 0 && x < 5;
		assert x >= 0 && y < 5;
		int laneByteCount = getLaneLengthInBits() / Byte.SIZE;
		int inputByteStartIndex = inputBitIndex / Byte.SIZE;
		int laneValue = 0;
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
				laneArray[x][y] = laneArray[x][y] ^ (1 << z);
			}
			if (++z == getLaneLengthInBits()) {
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
		laneArray[1][0] = not(laneArray[1][0]);
		laneArray[2][0] = not(laneArray[2][0]);
		laneArray[3][1] = not(laneArray[3][1]);
		laneArray[2][2] = not(laneArray[2][2]);
		laneArray[2][3] = not(laneArray[2][3]);
		laneArray[0][4] = not(laneArray[0][4]);
	}

	private int not(int lane) {
		int inverted = lane ^ getLaneMask();
		return inverted;
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
		d[0] = c[4] ^ rotateLane(c[1], 1);
		d[1] = c[0] ^ rotateLane(c[2], 1);
		d[2] = c[1] ^ rotateLane(c[3], 1);
		d[3] = c[2] ^ rotateLane(c[4], 1);
		d[4] = c[3] ^ rotateLane(c[0], 1);
	}

	private int rotateLane(int lane, int rotateBy) {
		assert rotateBy >= 0 && rotateBy < getLaneLengthInBits();
		int result = (lane << rotateBy) | (lane >>> (getLaneLengthInBits()
				- rotateBy));
		return result & getLaneMask();
	}

	@Override
	void rhoPi() {
		b[0][0] = rotateLane(laneArray[0][0],
				getRotationConstantForLane(0, 0));
		b[1][3] = rotateLane(laneArray[0][1],
				getRotationConstantForLane(0, 1));
		b[2][1] = rotateLane(laneArray[0][2],
				getRotationConstantForLane(0, 2));
		b[3][4] = rotateLane(laneArray[0][3],
				getRotationConstantForLane(0, 3));
		b[4][2] = rotateLane(laneArray[0][4],
				getRotationConstantForLane(0, 4));

		b[0][2] = rotateLane(laneArray[1][0],
				getRotationConstantForLane(1, 0));
		b[1][0] = rotateLane(laneArray[1][1],
				getRotationConstantForLane(1, 1));
		b[2][3] = rotateLane(laneArray[1][2],
				getRotationConstantForLane(1, 2));
		b[3][1] = rotateLane(laneArray[1][3],
				getRotationConstantForLane(1, 3));
		b[4][4] = rotateLane(laneArray[1][4],
				getRotationConstantForLane(1, 4));

		b[0][4] = rotateLane(laneArray[2][0],
				getRotationConstantForLane(2, 0));
		b[1][2] = rotateLane(laneArray[2][1],
				getRotationConstantForLane(2, 1));
		b[2][0] = rotateLane(laneArray[2][2],
				getRotationConstantForLane(2, 2));
		b[3][3] = rotateLane(laneArray[2][3],
				getRotationConstantForLane(2, 3));
		b[4][1] = rotateLane(laneArray[2][4],
				getRotationConstantForLane(2, 4));

		b[0][1] = rotateLane(laneArray[3][0],
				getRotationConstantForLane(3, 0));
		b[1][4] = rotateLane(laneArray[3][1],
				getRotationConstantForLane(3, 1));
		b[2][2] = rotateLane(laneArray[3][2],
				getRotationConstantForLane(3, 2));
		b[3][0] = rotateLane(laneArray[3][3],
				getRotationConstantForLane(3, 3));
		b[4][3] = rotateLane(laneArray[3][4],
				getRotationConstantForLane(3, 4));

		b[0][3] = rotateLane(laneArray[4][0],
				getRotationConstantForLane(4, 0));
		b[1][1] = rotateLane(laneArray[4][1],
				getRotationConstantForLane(4, 1));
		b[2][4] = rotateLane(laneArray[4][2],
				getRotationConstantForLane(4, 2));
		b[3][2] = rotateLane(laneArray[4][3],
				getRotationConstantForLane(4, 3));
		b[4][0] = rotateLane(laneArray[4][4],
				getRotationConstantForLane(4, 4));
	}

	@Override
	void chi() {
		for (int y = 0; y < 5; ++y) {
			laneArray[0][y] = b[0][y] ^ (not(b[1][y]) & b[2][y]);
			laneArray[1][y] = b[1][y] ^ (not(b[2][y]) & b[3][y]);
			laneArray[2][y] = b[2][y] ^ (not(b[3][y]) & b[4][y]);
			laneArray[3][y] = b[3][y] ^ (not(b[4][y]) & b[0][y]);
			laneArray[4][y] = b[4][y] ^ (not(b[0][y]) & b[1][y]);
		}
	}

	@Override
	void chiWithLaneComplementingTransform() {
		int invertedLaneTwoZero = not(b[2][0]);
		laneArray[0][0] = b[0][0] ^ (b[1][0] | b[2][0]);
		laneArray[1][0] = b[1][0] ^ (invertedLaneTwoZero | b[3][0]);
		laneArray[2][0] = b[2][0] ^ (b[3][0] & b[4][0]);
		laneArray[3][0] = b[3][0] ^ (b[4][0] | b[0][0]);
		laneArray[4][0] = b[4][0] ^ (b[0][0] & b[1][0]);

		int invertedLaneFourOne = not(b[4][1]);
		laneArray[0][1] = b[0][1] ^ (b[1][1] | b[2][1]);
		laneArray[1][1] = b[1][1] ^ (b[2][1] & b[3][1]);
		laneArray[2][1] = b[2][1] ^ (b[3][1] | invertedLaneFourOne);
		laneArray[3][1] = b[3][1] ^ (b[4][1] | b[0][1]);
		laneArray[4][1] = b[4][1] ^ (b[0][1] & b[1][1]);

		int invertedLaneThreeTwo = not(b[3][2]);
		laneArray[0][2] = b[0][2] ^ (b[1][2] | b[2][2]);
		laneArray[1][2] = b[1][2] ^ (b[2][2] & b[3][2]);
		laneArray[2][2] = b[2][2] ^ (invertedLaneThreeTwo & b[4][2]);
		laneArray[3][2] = invertedLaneThreeTwo ^ (b[4][2] | b[0][2]);
		laneArray[4][2] = b[4][2] ^ (b[0][2] & b[1][2]);

		int invertedLaneThreeThree = not(b[3][3]);
		laneArray[0][3] = b[0][3] ^ (b[1][3] & b[2][3]);
		laneArray[1][3] = b[1][3] ^ (b[2][3] | b[3][3]);
		laneArray[2][3] = b[2][3] ^ (invertedLaneThreeThree | b[4][3]);
		laneArray[3][3] = invertedLaneThreeThree ^ (b[4][3] & b[0][3]);
		laneArray[4][3] = b[4][3] ^ (b[0][3] | b[1][3]);

		int invertedLaneOneFour = not(b[1][4]);
		laneArray[0][4] = b[0][4] ^ (invertedLaneOneFour & b[2][4]);
		laneArray[1][4] = invertedLaneOneFour ^ (b[2][4] | b[3][4]);
		laneArray[2][4] = b[2][4] ^ (b[3][4] & b[4][4]);
		laneArray[3][4] = b[3][4] ^ (b[4][4] | b[0][4]);
		laneArray[4][4] = b[4][4] ^ (b[0][4] & b[1][4]);
	}

	@Override
	void iota(int roundIndex) {
		assert roundIndex >= 0 && roundIndex < getNumberOfRoundsPerPermutation();
		laneArray[0][0] = laneArray[0][0]
				^ getRoundConstantForRound(roundIndex);
	}

	@Override
	void squeezeEntireLaneIntoOutput(int x, int y, byte[] output,
			int outputBitIndex) {
		assert x >= 0 && x < 5;
		assert y >= 0 && y < 5;
		assert output != null;
		assert outputBitIndex >= 0;
		long laneValue = laneArray[x][y];
		int laneByteCount = getLaneLengthInBits() / Byte.SIZE;
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
		for (int z = 0; z < getLaneLengthInBits(); ++z) {
			if (outputBitIndex == outputStopIndex) {
				break;
			}
			boolean bitHigh = (laneArray[x][y] & (1 << z)) != 0;
			if (bitHigh) {
				setOutputBitHigh(output, outputBitIndex);
			}
			++outputBitIndex;
		}
		return outputBitIndex;
	}

}
