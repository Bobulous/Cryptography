/*
 * Copyright © 2017 Bobulous <http://www.bobulous.org.uk/>.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/.
 */
package uk.org.bobulous.java.crypto.keccak;

import java.util.BitSet;

/**
 * Functions related to Keccak, most of which are no longer directly used by the
 * classes within this package.
 * <p>
 * As an example, the methods within this class were used to generate the
 * rotation constants and round constants which are now hardcoded into the
 * respective KeccakState subclasses for each permutation width.</p>
 */
class KeccakUtilities {

	/**
	 * The rotation constants used in the rho permutation step. The values here
	 * assume a lane length of 64 bits, and must be adjusted for any Keccak
	 * sponge function which uses shorter lanes.
	 */
	private static final byte[][] RAW_ROTATION_CONSTANTS;

	static {
		byte[][] rotOffsets = new byte[5][5];
		rotOffsets[0] = new byte[]{(byte) 0,
			(byte) 36,
			(byte) 3,
			(byte) 41,
			(byte) 18};
		rotOffsets[1] = new byte[]{(byte) 1,
			(byte) 44,
			(byte) 10,
			(byte) 45,
			(byte) 2};
		rotOffsets[2] = new byte[]{(byte) 62,
			(byte) 6,
			(byte) 43,
			(byte) 15,
			(byte) 61};
		rotOffsets[3] = new byte[]{(byte) 28,
			(byte) 55,
			(byte) 25,
			(byte) 21,
			(byte) 56};
		rotOffsets[4] = new byte[]{(byte) 27,
			(byte) 20,
			(byte) 39,
			(byte) 8,
			(byte) 14};
		RAW_ROTATION_CONSTANTS = rotOffsets;
	}

	/**
	 * Returns a two-dimensional array of rotation offset values which apply to
	 * a Keccak sponge with the given lane length.
	 *
	 * @return a 5×5 byte array which contains the rotation offsets, such that
	 * {@code result[x][y]} will contain the rotation offset which should be
	 * applied to lane [x][y] by the rho transform during permutation.
	 */
	static byte[][] getRotationConstantsForLaneLength(int laneLength) {
		if (laneLength == 64) {
			return RAW_ROTATION_CONSTANTS;
		}
		byte[][] moduloRotations = new byte[5][5];
		for (int x = 0; x < 5; ++x) {
			for (int y = 0; y < 5; ++y) {
				moduloRotations[x][y] = (byte) (RAW_ROTATION_CONSTANTS[x][y]
						% laneLength);
			}
		}
		return moduloRotations;
	}

	/**
	 * Calculates the round constant values which apply to a Keccak sponge
	 * function with the given lane length. The returned array will contain one
	 * value for each round, to be applied during the iota transform of the
	 * permutation.
	 * <p>
	 * <strong>Important:</strong> the returned array will contain {@code long}
	 * values, which will need to be cast to {@code int} values (or smaller) if
	 * the target sponge is not using {@code long} values to represent the lanes
	 * in its permutation state.</p>
	 *
	 * @return a {@code long[]} such that each array index aligns with a
	 * permutation round index.
	 */
	long[] buildRoundConstants(int laneLength) {
		assert laneLength > 0 && laneLength <= 64;
		int numberOfRoundsPerPermutation
				= getNumberOfRoundsPerPermutationWithLaneLength(laneLength);
		long[] array = new long[numberOfRoundsPerPermutation];
		int l = getBinaryExponent(laneLength);
		for (int roundIndex = 0; roundIndex < numberOfRoundsPerPermutation;
				++roundIndex) {
			long roundConstant = 0L;
			for (int j = 0; j <= l; ++j) {
				int index = (int) Math.pow(2.0, j) - 1;
				boolean isHigh = rc(j + 7 * roundIndex);
				if (isHigh) {
					roundConstant += 1L << index;
				}
			}
			array[roundIndex] = roundConstant;
		}
		return array;
	}

	/**
	 * Returns the number of rounds (within every permutation) which should be
	 * applied for a Keccak sponge with the specified lane length.
	 *
	 * @param laneLength the length of each lane, in bits.
	 * @return the number of rounds for each permutation.
	 */
	static byte getNumberOfRoundsPerPermutationWithLaneLength(int laneLength) {
		switch (laneLength) {
			case 1:
				return 12;
			case 2:
				return 14;
			case 4:
				return 16;
			case 8:
				return 18;
			case 16:
				return 20;
			case 32:
				return 22;
			case 64:
				return 24;
			default:
				throw new IllegalArgumentException("Illegal lane size: "
						+ laneLength);
		}
	}

	/**
	 * Returns the base two logarithm of the supplied lane length. The resulting
	 * exponent is used in calculating round constants.
	 *
	 * @param laneLength the length of each lane, in bits.
	 * @return the base two logarithm of the given lane length.
	 */
	static byte getBinaryExponent(int laneLength) {
		switch (laneLength) {
			case 1:
				return 0;
			case 2:
				return 1;
			case 4:
				return 2;
			case 8:
				return 3;
			case 16:
				return 4;
			case 32:
				return 5;
			case 64:
				return 6;
			default:
				throw new IllegalArgumentException("Illegal lane size: "
						+ laneLength);
		}
	}

	/**
	 * Used as part of the calculation of the Round Constant.
	 * <p>
	 * This code is based on "Algorithm 5: rc(t)" in
	 * <a href="http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf">FIPS
	 * PUB 202</a>.
	 * </p>
	 */
	static boolean rc(int t) {
		assert t >= 0 && t <= 167;
		t = t % 255;
		if (t == 0) {
			return true;
		}
		BitSet r = new BitSet(8 + t);
		int zeroIndex = t;
		r.set(zeroIndex, true);
		for (int i = 1; i <= t; ++i) {
			--zeroIndex;
			r.set(zeroIndex, r.get(zeroIndex) ^ r.get(zeroIndex + 8));
			r.set(zeroIndex + 4, r.get(zeroIndex + 4) ^ r.get(zeroIndex + 8));
			r.set(zeroIndex + 5, r.get(zeroIndex + 5) ^ r.get(zeroIndex + 8));
			r.set(zeroIndex + 6, r.get(zeroIndex + 6) ^ r.get(zeroIndex + 8));
		}
		return r.get(zeroIndex);
	}

}
