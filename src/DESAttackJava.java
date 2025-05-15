import java.util.Arrays;

class Message {
    long chiffrerHexa;
    int[] chiffrerBinaire = new int[64];
    int[] chiffrerBinairePermuter = new int[64];
    int[] leftChiffrer = new int[32];
    int[] rightChiffrer = new int[32];
    int[] rightChiffrerExp = new int[48];
    int[] sbox6Bits = new int[6];
    int[] sbox6BitsXorer = new int[6];
    int[] sbox4Bits = new int[4];
}

class Key {
    int[] key48bit = new int[48];
    int[] key56bit = new int[56];
    int[] key64bitb = new int[64];
    int[] key8bit = new int[8];
}

class DesState {
    int[] claireBinaire = new int[64];
    int[] key64Bit = new int[64];
    int[] claireBinaireIp = new int[64];
    int[] right32Bit = new int[32];
    int[] left32Bit = new int[32];
    int[] right32BitPlus1 = new int[32];
    int[] left32BitPlus1 = new int[32];
    // int[] right48Bit = new int[48];
    int[][] subKey = new int[16][48];
    int[] chiffrerBinaire = new int[64];
}

public class DESAttackJava {

    // --- DES TABLES and CONSTANTS ---
    private static final int[] IP = {
            58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
    };
    private static final int[] IP_MOIN_1 = {
            40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25
    };
    private static final int[] E = {
            32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1
    };
    private static final int[] P = {
            16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
            2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25
    };
    private static final int[] P_MOIN_1 = {
            9, 17, 23, 31, 13, 28, 2, 18, 24, 16, 30, 6, 26, 20, 10, 1,
            8, 14, 25, 3, 4, 29, 11, 19, 32, 12, 22, 7, 5, 27, 15, 21
    };
    private static final int[][][] SBOX = {
            {{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7}, {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8}, {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0}, {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}},
            {{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10}, {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5}, {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15}, {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}},
            {{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8}, {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1}, {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7}, {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}},
            {{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15}, {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9}, {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4}, {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}},
            {{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9}, {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6}, {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14}, {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}},
            {{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11}, {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8}, {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6}, {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}},
            {{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1}, {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6}, {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2}, {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}},
            {{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7}, {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2}, {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8}, {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}}
    };
    private static final int[] PC1 = {
            57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4
    };
    private static final int[] PC1_MOIN_1 = { // "Inverse" of PC1 for key reconstruction
            8, 16, 24, 56, 52, 44, 36, 0, 7, 15, 23, 55, 51, 43, 35, 0,
            6, 14, 22, 54, 50, 42, 34, 0, 5, 13, 21, 53, 49, 41, 33, 0,
            4, 12, 20, 28, 48, 40, 32, 0, 3, 11, 19, 27, 47, 39, 31, 0,
            2, 10, 18, 26, 46, 38, 30, 0, 1, 9, 17, 25, 45, 37, 29, 0
    };
    private static final int[] PC2 = {
            14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8,
            16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
    };
    private static final int[] PC2_MOIN_1 = { // "Inverse" of PC2 for key reconstruction
            5, 24, 7, 16, 6, 10, 20, 18, 0, 12, 3, 15, 23, 1, 9, 19,
            2, 0, 14, 22, 11, 0, 13, 4, 0, 17, 21, 8, 47, 31, 27, 48,
            35, 41, 0, 46, 28, 0, 39, 32, 25, 44, 0, 37, 34, 43, 29,
            36, 38, 45, 33, 26, 42, 0, 30, 40
    };

    private static final long MESSAGE_CLAIRE = 0xAE2AD5A74FF82634L;
    private static final long CHIFFRER_JUSTE = 0x52E4186D3632B556L;
    private static final long[] CHIFFRER_FAUX = {
            0x53E4146D6626B554L, 0x1264087D3632FD56L, 0x4FA41D6C2606B556L, 0x46E1586DB632B172L,
            0x53F41C6B3632B756L, 0x46E4116C3602B556L, 0x539418293433B416L, 0xD6E4195D3232E156L,
            0x52E11A293632B5C2L, 0x53C4186D2632B616L, 0x10E50869367BB553L, 0x56E4096D1272B41FL,
            0x52E418FD37323142L, 0x12E40A2D367BB557L, 0x52E9186CF726F552L, 0x32E418647236B416L,
            0x46E4D86D3632F176L, 0x52E9186C76263556L, 0xC3A41D7D3630F156L, 0x13E40C6D2E22B555L,
            0x42E4184D32328556L, 0x53A49C6D3730B156L, 0x56F619691633A416L, 0x5AF41C6A2626B556L,
            0x52E4286D3272A55FL, 0x52F6596936339556L, 0x72E5086D32F2B402L, 0x53A118293432B5C2L,
            0x12E418647676BD56L, 0x52E5386D32B2B442L, 0x1264087C7E32F557L, 0x50E418F93733B142L
    };


    public static void hexToBinary(int[] tabResult, long hexa, int nbrHexaDigits) {
        long tmp = hexa;
        int bitIndex = nbrHexaDigits * 4 - 1;
        for (int j = 0; j < nbrHexaDigits; j++) {
            int quartet = (int) (tmp & 0xF);
            for (int i = 0; i < 4; i++) {
                if (bitIndex >= 0) {
                    tabResult[bitIndex] = (quartet >> i) & 1; // Correct order for LSB of quartet
                }
                bitIndex--;
            }
            tmp = tmp >> 4;
        }
        // Reverse individual quartet bits as C code fills from rightmost bit of quartet first
        for (int i = 0; i < nbrHexaDigits * 4; i += 4) {
            int temp;
            temp = tabResult[i]; tabResult[i] = tabResult[i+3]; tabResult[i+3] = temp;
            temp = tabResult[i+1]; tabResult[i+1] = tabResult[i+2]; tabResult[i+2] = temp;
        }
    }
    public static void hexToBinaryPrecise(int[] tabResult, long hexa, int nbrHexaDigits) {
        long tempHex = hexa;
        int compteur = nbrHexaDigits * 4 - 1;
        for (int j = 0; j < nbrHexaDigits; j++) {
            int entier = (int) (tempHex & 0xF);
            for (int i = 0; i < 4; i++) {
                if (compteur >=0) tabResult[compteur] = entier % 2;
                entier = entier / 2;
                compteur--;
            }
            tempHex = tempHex >> 4;
        }
    }


    public static void decimalToBinary(int[] tabResult, int decimal, int nbrBit) {
        int entier = decimal;
        for (int i = nbrBit - 1; i >= 0; i--) {
            tabResult[i] = entier % 2;
            entier = entier / 2;
        }
    }

    public static int arrayToInt(int[] tab, int nbrBit) {
        int nombre = 0;
        for (int i = 0; i < nbrBit; i++) {
            if (tab[i] != 0) {
                nombre |= (1 << (nbrBit - 1 - i));
            }
        }
        return nombre;
    }

    public static long arrayToLong(int[] tab, int nbrBit) {
        long nombre = 0;
        int k = 0;
        for (int j = nbrBit - 1; j >= 0; j--) {
            if (tab[j] != 0) {
                nombre += (1L << k);
            }
            k++;
        }
        return nombre;
    }


    public static void permutation(int[] resultat, int[] aPermuter, final int[] tablePermutation, int nbrBit) {
        int[] source = Arrays.copyOf(aPermuter, aPermuter.length);

        for (int i = 0; i < nbrBit; i++) {
            if (tablePermutation[i] != 0) {
                resultat[i] = source[tablePermutation[i] - 1];
            } else {

            }
        }
    }

    public static void splitArray(int[] completTab, int[] leftTab, int[] rightTab, int nbrBitDemi) {
        System.arraycopy(completTab, 0, leftTab, 0, nbrBitDemi);
        System.arraycopy(completTab, nbrBitDemi, rightTab, 0, nbrBitDemi);
    }

    public static void xorArrays(int[] tabResult, int[] premierK, int[] deuxiemeK, int nbrBit) {
        for (int i = 0; i < nbrBit; i++) {
            tabResult[i] = premierK[i] ^ deuxiemeK[i];
        }
    }

    public static int findFaultyBit(int[] tabJuste, int[] tabFaux) {
        int[] tabxor = new int[32];
        xorArrays(tabxor, tabJuste, tabFaux, 32);
        for (int j = 0; j < 32; j++) {
            if (tabxor[j] == 1) {
                return j; // 0-indexed
            }
        }
        return -1;
    }

    public static void sboxFunction(int[] resultat4bit, int[] entrer6bit, int numSbox) {
        int row = entrer6bit[0] * 2 + entrer6bit[5];
        int column = entrer6bit[1] * 8 + entrer6bit[2] * 4 + entrer6bit[3] * 2 + entrer6bit[4];
        int valSbox = SBOX[numSbox][row][column];
        decimalToBinary(resultat4bit, valSbox, 4);
    }

    public static void getR16L16(long hexa, Message m) {
        m.chiffrerHexa = hexa;
        hexToBinaryPrecise(m.chiffrerBinaire, hexa, 16);
        permutation(m.chiffrerBinairePermuter, m.chiffrerBinaire, IP, 64);
        splitArray(m.chiffrerBinairePermuter, m.leftChiffrer, m.rightChiffrer, 32);
    }

    public static void extract6Bits(Message m, int positionSBox) {
        for (int i = 0; i < 6; i++) {
            m.sbox6Bits[i] = m.rightChiffrerExp[6 * positionSBox + i];
        }
    }

    public static void initArray(int[] tab, int val, int nbrBit) {
        Arrays.fill(tab, 0, nbrBit, val);
    }
    public static void initArray(int[] tab, int val) {
        Arrays.fill(tab, val);
    }


    public static void leftShift(int[] resultat, int[] tabToShift, int numShifts, int numBits) {
        int[] temp = Arrays.copyOf(tabToShift, numBits);
        for (int i = 0; i < numBits; i++) {
            resultat[i] = temp[(i + numShifts) % numBits];
        }
    }

    public static void fuseArrays(int[] resultat, int[] leftTab, int[] rightTab, int nbrBitDemi) {
        System.arraycopy(leftTab, 0, resultat, 0, nbrBitDemi);
        System.arraycopy(rightTab, 0, resultat, nbrBitDemi, nbrBitDemi);
    }

    public static void copyArray(int[] resultat, int[] aCopier, int nbrBit) {
        System.arraycopy(aCopier, 0, resultat, 0, nbrBit);
    }

    public static long k16ToHex(int[][] tabK16Counts) {
        long resultatK16Hex;
        int[] k16_6bitFragments = new int[8];
        int[] k16_48bitBinary = new int[48];
        int[] temp6bitBinary = new int[6];

        System.out.println("Fragments K16 (valeur 0-63) et leur max_count:");
        for (int i = 0; i < 8; i++) {
            int maxCount = -1;
            int bestJ = 0;
            for (int j = 0; j < 64; j++) {
                if (tabK16Counts[i][j] > maxCount) {
                    maxCount = tabK16Counts[i][j];
                    bestJ = j;
                }
            }
            k16_6bitFragments[i] = bestJ;
            System.out.printf("S-box %d: fragment_val=%d (max_count=%d)\n", i, k16_6bitFragments[i], maxCount);
            decimalToBinary(temp6bitBinary, k16_6bitFragments[i], 6);
            for (int bitIdx = 0; bitIdx < 6; bitIdx++) {
                k16_48bitBinary[i * 6 + bitIdx] = temp6bitBinary[bitIdx];
            }
        }
        resultatK16Hex = arrayToLong(k16_48bitBinary, 48);
        System.out.print("K16 binaire construite: ");
        for (int i = 0; i < 48; i++) System.out.print(k16_48bitBinary[i]);
        System.out.println();
        return resultatK16Hex;
    }

    public static long exhaustiveSearchK16(long leChiffrerJuste, long[] lesChiffrerFaux) {
        Message juste = new Message();
        Message faux = new Message();
        int[][] k16SboxFragmentCounts = new int[8][64];
        for(int i=0; i<8; i++) Arrays.fill(k16SboxFragmentCounts[i],0);


        getR16L16(leChiffrerJuste, juste);

        int[] diffL16Permuted = new int[32];
        int[] diffL16Unpermuted = new int[32];

        for (int w = 0; w < 32; w++) {
            getR16L16(lesChiffrerFaux[w], faux);

            xorArrays(diffL16Unpermuted, juste.leftChiffrer, faux.leftChiffrer, 32);
            permutation(diffL16Permuted, diffL16Unpermuted, P_MOIN_1, 32);

            int faultyBitInR16 = findFaultyBit(juste.rightChiffrer, faux.rightChiffrer);
            if (faultyBitInR16 == -1) {
                System.out.printf("Attention: Chiffré faux %d identique à chiffré juste pour R16. Skip.\n", w);
                continue;
            }

            permutation(juste.rightChiffrerExp, juste.rightChiffrer, E, 48);
            permutation(faux.rightChiffrerExp, faux.rightChiffrer, E, 48);

            int[] outputSboxDiffTarget = new int[4];
            int[] currentK16Fragment6bit = new int[6];
            int[] calculatedSboxOutputDiff = new int[4];

            for (int bitExpIdx = 0; bitExpIdx < 48; bitExpIdx++) {
                if (E[bitExpIdx] == (faultyBitInR16 + 1)) {
                    int sboxIdxAffected = bitExpIdx / 6;

                    extract6Bits(juste, sboxIdxAffected);
                    extract6Bits(faux, sboxIdxAffected);

                    for (int y = 0; y < 4; y++) {
                        outputSboxDiffTarget[y] = diffL16Permuted[4 * sboxIdxAffected + y];
                    }

                    for (int k16FragVal = 0; k16FragVal < 64; k16FragVal++) {
                        decimalToBinary(currentK16Fragment6bit, k16FragVal, 6);

                        xorArrays(juste.sbox6BitsXorer, juste.sbox6Bits, currentK16Fragment6bit, 6);
                        sboxFunction(juste.sbox4Bits, juste.sbox6BitsXorer, sboxIdxAffected);

                        xorArrays(faux.sbox6BitsXorer, faux.sbox6Bits, currentK16Fragment6bit, 6);
                        sboxFunction(faux.sbox4Bits, faux.sbox6BitsXorer, sboxIdxAffected);

                        xorArrays(calculatedSboxOutputDiff, juste.sbox4Bits, faux.sbox4Bits, 4);

                        if (Arrays.equals(outputSboxDiffTarget, calculatedSboxOutputDiff)) {
                            k16SboxFragmentCounts[sboxIdxAffected][k16FragVal]++;
                        }
                    }
                }
            }
        }
        return k16ToHex(k16SboxFragmentCounts);
    }

    public static void generateSubKeys(int[][] les16SubKey, int[] key64BitBinary) {
        int[] vShifts = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};
        int[] key56bitPermutedPC1 = new int[56];
        int[] cHalf = new int[28];
        int[] dHalf = new int[28];

        permutation(key56bitPermutedPC1, key64BitBinary, PC1, 56);
        splitArray(key56bitPermutedPC1, cHalf, dHalf, 28);

        for (int i = 0; i < 16; i++) {
            leftShift(cHalf, cHalf, vShifts[i], 28);
            leftShift(dHalf, dHalf, vShifts[i], 28);
            fuseArrays(key56bitPermutedPC1, cHalf, dHalf, 28);
            permutation(les16SubKey[i], key56bitPermutedPC1, PC2, 48);
        }
    }

    public static void internalFFunction(int[] resultat32bit, int[] rInput32bit, int[] kSubKey48bit) {
        int[] eR48bit = new int[48];
        int[] xorResult48bit = new int[48];
        int[] sboxInput6bit = new int[6];
        int[] sboxOutput4bit = new int[4];
        int[] sboxOutputsConcat32bit = new int[32];

        permutation(eR48bit, rInput32bit, E, 48);
        xorArrays(xorResult48bit, eR48bit, kSubKey48bit, 48);

        for (int sboxIdx = 0; sboxIdx < 8; sboxIdx++) {
            for (int bitIdx = 0; bitIdx < 6; bitIdx++) {
                sboxInput6bit[bitIdx] = xorResult48bit[6 * sboxIdx + bitIdx];
            }
            sboxFunction(sboxOutput4bit, sboxInput6bit, sboxIdx);
            for (int bitIdx = 0; bitIdx < 4; bitIdx++) {
                sboxOutputsConcat32bit[sboxIdx * 4 + bitIdx] = sboxOutput4bit[bitIdx];
            }
        }
        permutation(resultat32bit, sboxOutputsConcat32bit, P, 32);
    }

    public static long desFunction(long claireHex, long k64Hex) {
        DesState dState = new DesState();
        int[] fResult32bit = new int[32];
        int[] finalConcatBeforeIPinv = new int[64];

        hexToBinaryPrecise(dState.claireBinaire, claireHex, 16);
        hexToBinaryPrecise(dState.key64Bit, k64Hex, 16);

        permutation(dState.claireBinaireIp, dState.claireBinaire, IP, 64);
        splitArray(dState.claireBinaireIp, dState.left32Bit, dState.right32Bit, 32);

        generateSubKeys(dState.subKey, dState.key64Bit);

        for (int round = 0; round < 16; round++) {
            copyArray(dState.left32BitPlus1, dState.right32Bit, 32);
            internalFFunction(fResult32bit, dState.right32Bit, dState.subKey[round]);
            xorArrays(dState.right32BitPlus1, dState.left32Bit, fResult32bit, 32);

            copyArray(dState.left32Bit, dState.left32BitPlus1, 32);
            copyArray(dState.right32Bit, dState.right32BitPlus1, 32);
        }

        fuseArrays(finalConcatBeforeIPinv, dState.right32Bit, dState.left32Bit, 32);
        permutation(dState.chiffrerBinaire, finalConcatBeforeIPinv, IP_MOIN_1, 64);
        return arrayToLong(dState.chiffrerBinaire, 64);
    }

    public static long getK56bit(long claireHex, long chiffrerHexAttendu, long k16Hex) {
        Key kStruct = new Key();
        initArray(kStruct.key48bit,0);
        initArray(kStruct.key56bit,0);
        initArray(kStruct.key64bitb,0);

        hexToBinaryPrecise(kStruct.key48bit, k16Hex, 12);
        permutation(kStruct.key56bit, kStruct.key48bit, PC2_MOIN_1, 56);
        permutation(kStruct.key64bitb, kStruct.key56bit, PC1_MOIN_1, 64);

        int[] position8bitBruteforce = {14, 15, 19, 20, 51, 54, 58, 60}; // 1-indexed

        System.out.print("Clé 64 bits après PC1_MOIN_1 (avant bruteforce des 8 bits):\n");
        for (int i = 0; i < 64; i++) {
            System.out.print(kStruct.key64bitb[i]);
            if ((i + 1) % 8 == 0) System.out.print(" ");
        }
        System.out.println();

        for (int iBruteforce = 0; iBruteforce < 256; iBruteforce++) {
            decimalToBinary(kStruct.key8bit, iBruteforce, 8);
            for (int j = 0; j < 8; j++) {
                kStruct.key64bitb[position8bitBruteforce[j] - 1] = kStruct.key8bit[j];
            }
            long currentKeyCandidateHex = arrayToLong(kStruct.key64bitb, 64);
            if (chiffrerHexAttendu == desFunction(claireHex, currentKeyCandidateHex)) {
                System.out.printf("Clé 56-bit (effective) trouvée (avant ajustement parité)! Hex: %016x\n", currentKeyCandidateHex);
                return currentKeyCandidateHex;
            }
        }
        System.out.println("Aucune clé trouvée dans getK56bit après 256 essais.");
        return 0L;
    }

    public static long getK64bitParity(long claireHex, long chiffrerHexAttendu, long k16Hex) {
        int compteurParite;
        int[] tabClefB64bit = new int[64];
        long keySansPariteHex = getK56bit(claireHex, chiffrerHexAttendu, k16Hex);

        if (keySansPariteHex == 0L) {
            System.out.println("getK56bit n'a pas trouvé de clé, impossible d'ajuster la parité.");
            return 0L;
        }

        hexToBinaryPrecise(tabClefB64bit, keySansPariteHex, 16);
        System.out.print("Clé avant ajustement parité (binaire):\n");
        for (int i = 0; i < 64; i++) {
            System.out.print(tabClefB64bit[i]);
            if ((i + 1) % 8 == 0) System.out.print(" ");
        }
        System.out.println();

        for (int byteIdx = 0; byteIdx < 8; byteIdx++) {
            compteurParite = 0;
            for (int bitIdx = 0; bitIdx < 7; bitIdx++) {
                compteurParite += tabClefB64bit[byteIdx * 8 + bitIdx];
            }
            if (compteurParite % 2 == 0) {
                tabClefB64bit[byteIdx * 8 + 7] = 1;
            } else {
                tabClefB64bit[byteIdx * 8 + 7] = 0;
            }
        }

        System.out.print("Clé après ajustement parité (binaire):\n");
        for (int i = 0; i < 64; i++) {
            System.out.print(tabClefB64bit[i]);
            if ((i + 1) % 8 == 0) System.out.print(" ");
        }
        System.out.println();
        return arrayToLong(tabClefB64bit, 64);
    }

    public static void testDES() {
        System.out.println("\n--- Test DES Standard ---");
        long p1 = 0x0123456789ABCDEFL;
        long k1 = 0x133457799BBCDFF1L;
        long c1Attendu = 0x85E813540F0AB405L;
        long c1Calcule = desFunction(p1, k1);
        System.out.println("Test 1:");
        System.out.printf("Clair : %016x\n", p1);
        System.out.printf("Clé   : %016x\n", k1);
        System.out.printf("Chiffré Attendu: %016x\n", c1Attendu);
        System.out.printf("Chiffré Calculé: %016x\n", c1Calcule);
        if (c1Calcule == c1Attendu) {
            System.out.println("Test 1 DES: SUCCÈS");
        } else {
            System.out.println("Test 1 DES: ÉCHEC");
        }

        long p2 = 0x0000000000000000L;
        long k2 = 0x0123456789ABCDEFL;
        long c2Attendu = 0x8CA64DE9C1B123A6L;
        long c2Calcule = desFunction(p2, k2);

        System.out.println("--- Fin Test DES ---\n");
    }

    public static void main(String[] args) {
        testDES();

        long k16Hex = exhaustiveSearchK16(CHIFFRER_JUSTE, CHIFFRER_FAUX);
        System.out.printf("K16 trouvée (hex) : %012x\n", k16Hex);

        if (k16Hex == 0L && !(  false) ) {
            System.out.println("La recherche de K16 semble avoir échoué (K16 = 0 ou faible confiance).");
        }

        long clefFinaleAvecParite = getK64bitParity(MESSAGE_CLAIRE, CHIFFRER_JUSTE, k16Hex);
        if (clefFinaleAvecParite != 0L) {
            System.out.printf("Clé finale 64 bits (avec parité) : %016x\n", clefFinaleAvecParite);

            long testChiffre = desFunction(MESSAGE_CLAIRE, clefFinaleAvecParite);
            System.out.printf("Test avec clé trouvée: Chiffrement de %016x avec %016x -> %016x\n",
                    MESSAGE_CLAIRE, clefFinaleAvecParite, testChiffre);
            if (testChiffre == CHIFFRER_JUSTE) {
                System.out.println("VÉRIFICATION FINALE: SUCCÈS! La clé trouvée chiffre correctement le message.");
            } else {
                System.out.println("VÉRIFICATION FINALE: ÉCHEC! La clé trouvée NE chiffre PAS correctement le message.");
            }
        } else {
            System.out.println("Impossible de trouver la clé finale.");
        }
    }
}