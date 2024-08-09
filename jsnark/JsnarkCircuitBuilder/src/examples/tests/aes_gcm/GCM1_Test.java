package examples.tests.aes_gcm;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import junit.framework.TestCase;
import org.junit.Test;
import util.Util;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;

import examples.gadgets.aes_gcm.AES128WrapperGadget;
import examples.gadgets.aes_gcm.Xor16Gadget;


public class GCM1_Test extends TestCase {

	// description: encrypts the nonce||counter as iv to get the tagMask value
	// inputs 16 byte nonce||counter and 16 bytes key
	// returns tagMask ciphertext which is xored in AES gcm to derive tag
	@Test
	public void testCase1() {
		CircuitGenerator generator = new CircuitGenerator("Test1_Encrypt_IV") {

			private Wire[] iv_counter; // 12 byte nonce with 4 byte counter set to one
			private Wire[] key;
			private Wire[] tagMaskCipher;

			@Override
			protected void buildCircuit() {

				iv_counter = createInputWireArray(16); // hex encoded iv_counter created in go
				key = createProverWitnessWireArray(16); // 16 bytes key block
				tagMaskCipher = new AES128WrapperGadget(iv_counter, key).getOutputWires();
				makeOutputArray(tagMaskCipher);
			}

			@Override
			public void generateSampleInput(CircuitEvaluator evaluator) {

				// parsing iv_counter hex value, counter=1 in this case
				BigInteger ivctr = new BigInteger("3c819d9a9bed087615030b6500000001", 16);
				byte[] ivctrArray = ivctr.toByteArray();
				ivctrArray = Arrays.copyOfRange(ivctrArray, ivctrArray.length - 16, ivctrArray.length);
				for (int i = 0; i < 16; i++) {
					evaluator.setWireValue(iv_counter[i], (ivctrArray[i] & 0xff));
				}

				BigInteger keyK = new BigInteger("11754cd72aec309bf52f7687212e8957", 16); // 16 bytes zeros hex
				byte[] keyArray = keyK.toByteArray();
				keyArray = Arrays.copyOfRange(keyArray, keyArray.length - 16, keyArray.length);
				for (int i = 0; i < 16; i++) {
					evaluator.setWireValue(key[i], (keyArray[i] & 0xff));
				}
			}
		};

		generator.generateCircuit();
		CircuitEvaluator evaluator = new CircuitEvaluator(generator);
		generator.generateSampleInput(evaluator);
		evaluator.evaluate();

		ArrayList<Wire> resultWire = generator.getOutWires();
		BigInteger expCipher = new BigInteger("250327c674aaf477aef2675748cf6971", 16);	
		byte[] expCipherArray = expCipher.toByteArray();
		expCipherArray = Arrays.copyOfRange(expCipherArray, expCipherArray.length - 16, expCipherArray.length);

		for (int i = 0; i < 16; i++) {
			assertEquals(evaluator.getWireValue(resultWire.get(i)), BigInteger.valueOf((expCipherArray[i] + 256) % 256));
		}

	}


	// test 2 encrypts a 16 byte/128 bit zero array to generate the GHASH key H.
	// result ciphertext is used for galois field productTable
	@Test
	public void testCase2() {
		CircuitGenerator generator = new CircuitGenerator("Test2_Encrypt_16B_Zeros") {

			private Wire[] key;
			private Wire[] msg;
			private Wire[] gfKeyCipher;

			@Override
			protected void buildCircuit() {
				msg = createInputWireArray(16); // 16 bytes tag block
				key = createProverWitnessWireArray(16); // 16 bytes tag block
				gfKeyCipher = new AES128WrapperGadget(msg, key).getOutputWires();
				makeOutputArray(gfKeyCipher);
			}

			@Override
			public void generateSampleInput(CircuitEvaluator evaluator) {

				// setting zeros
				for (int i = 0; i < 16; i++) {
					evaluator.setWireValue(msg[i], BigInteger.ZERO);
				}
	
				// setting encryption key k
				BigInteger keyV = new BigInteger("11754cd72aec309bf52f7687212e8957", 16);
				byte[] keyArray = keyV.toByteArray();
				keyArray = Arrays.copyOfRange(keyArray, keyArray.length - 16, keyArray.length);
				for (int i = 0; i < 16; i++) {
					evaluator.setWireValue(key[i], (keyArray[i] & 0xff));
				}
			}
		};

		generator.generateCircuit();
		CircuitEvaluator evaluator = new CircuitEvaluator(generator);
		generator.generateSampleInput(evaluator);
		evaluator.evaluate();

		ArrayList<Wire> resultWire = generator.getOutWires();
		BigInteger expCipher = new BigInteger("13781e8ecd94c8b291e8f9613bdf32de", 16);	
		byte[] expCipherArray = expCipher.toByteArray();
		expCipherArray = Arrays.copyOfRange(expCipherArray, expCipherArray.length - 16, expCipherArray.length);
		for (int i = 0; i < 16; i++) {
			assertEquals(evaluator.getWireValue(resultWire.get(i)), BigInteger.valueOf((expCipherArray[i] + 256) % 256));
		}
	}

	// test 3: encrypts a 16 byte iv||counter block with counter=2 and xors the result with the plaintext.
	// result ciphertext is the ciphertext1 of plaintext1 chuck1
	@Test
	public void testCase3() {
		CircuitGenerator generator = new CircuitGenerator("Test3_Encrypt_16B_Plaintext1") {

			private Wire[] key;
			private Wire[] iv_counter;
			private Wire[] plaintext;
			private Wire[] tmpCipher;
			private Wire[] plaintextCipher1;

			@Override
			protected void buildCircuit() {

				iv_counter = createInputWireArray(16); // 16 bytes iv||counter block
				key = createProverWitnessWireArray(16); // 16 bytes key block
				plaintext = createProverWitnessWireArray(16); // 16 bytes plaintext block
				tmpCipher = new AES128WrapperGadget(iv_counter, key).getOutputWires();
				plaintextCipher1 = new Xor16Gadget(tmpCipher, plaintext).getOutputWires();
				makeOutputArray(plaintextCipher1);

			}

			@Override
			public void generateSampleInput(CircuitEvaluator evaluator) {

				// setting public iv||counter where counter=2
				BigInteger ivctr = new BigInteger("ee283a3fc75575e33efd488700000002", 16);
				byte[] ivctrArray = ivctr.toByteArray();
				ivctrArray = Arrays.copyOfRange(ivctrArray, ivctrArray.length - 16, ivctrArray.length);
				for (int i = 0; i < 16; i++) {
					evaluator.setWireValue(iv_counter[i], (ivctrArray[i] & 0xff));
				}
	
				// setting secret encryption key k
				BigInteger keyV = new BigInteger("7fddb57453c241d03efbed3ac44e371c", 16);
				byte[] keyArray = keyV.toByteArray();
				keyArray = Arrays.copyOfRange(keyArray, keyArray.length - 16, keyArray.length);
				for (int i = 0; i < 16; i++) {
					evaluator.setWireValue(key[i], (keyArray[i] & 0xff));
				}

				// setting secret plaintext
				BigInteger ptxt = new BigInteger("d5de42b461646c255c87bd2962d3b9a2", 16);
				byte[] ptxtArray = ptxt.toByteArray();
				ptxtArray = Arrays.copyOfRange(ptxtArray, ptxtArray.length - 16, ptxtArray.length);
				for (int i = 0; i < 16; i++) {
					evaluator.setWireValue(plaintext[i], (ptxtArray[i] & 0xff));
				}
			}
		};

		generator.generateCircuit();
		CircuitEvaluator evaluator = new CircuitEvaluator(generator);
		generator.generateSampleInput(evaluator);
		evaluator.evaluate();

		ArrayList<Wire> resultWire = generator.getOutWires();
		BigInteger expCipher = new BigInteger("2ccda4a5415cb91e135c2a0f78c9b2fd", 16);	
		//BigInteger expCipher = new BigInteger("f913e6112038d53b4fdb97261a1a0b5f", 16);	
		byte[] expCipherArray = expCipher.toByteArray();
		expCipherArray = Arrays.copyOfRange(expCipherArray, expCipherArray.length - 16, expCipherArray.length);
		for (int i = 0; i < 16; i++) {
			assertEquals(evaluator.getWireValue(resultWire.get(i)), BigInteger.valueOf((expCipherArray[i] + 256) % 256));
		}
	}

}

