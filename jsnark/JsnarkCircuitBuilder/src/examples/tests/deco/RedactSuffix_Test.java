package examples.tests.deco;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import examples.gadgets.blockciphers.AES128CBCGadget;
import examples.gadgets.hash.SHA256DECOGadget;
import examples.gadgets.hash.SHA256Gadget;
import junit.framework.TestCase;
import util.Util;

import java.util.Arrays;

public class RedactSuffix_Test extends TestCase {
    public void testCase1(){

        String inputStr = "54222c22706572736f6e616c2064617461223a7b22616765223a223230227d2c227072696365223a33383030302c2274696d65223a2231323a30303a3030222c22766f6c756d65223a3332313635347d";
        String siSHA256HexStr = "fdf9365ea88c95acf2829f59dc5541cc066533c3d02fbd844e088d1925a9d030";
        String ivLast3rdBlockHexStr = "cf793cdcf30898a732d11d8f6f263dfd";
        String keyMacStr = "a10ff895368427db4d380aa52a3fbd7374527e47dd1183f6bf463ef4b5e14c4b";
        String paddingStr = "0c0c0c0c0c0c0c0c0c0c0c0c0c";
        String expectedDigestStr = "fa1b65eda00d1a37fd45ed0c21e4d97fb56b933edf375a24ac7062d27296f256990269300f166705011e40c2811f271c";

        String keyEncStr = "60d1bb4f227b529766b5ec10bafd58b3";
        String plaintextInlast3rdBlockStr = "35347d";
        int previousLens = 128;


        CircuitGenerator generator = new CircuitGenerator("SHA256CompressionFunction_Test2") {

            Wire[] inputWires;
            Wire[] keyMacWires;

            Wire[] keyEncWires;
            Wire[] paddingWires;
            Wire[] siSHA256Wires;
            Wire[] ivLast3rdBlockWires;

            Wire[] plaintextInlast3rdBlockWires;

//            int paddingLength;

            @Override
            protected void buildCircuit() {
                CircuitGenerator generator = CircuitGenerator.getActiveCircuitGenerator();
                inputWires = createInputWireArray(inputStr.length()/2);
                keyMacWires = createInputWireArray(keyMacStr.length()/2);
                paddingWires = createInputWireArray(paddingStr.length()/2);
                siSHA256Wires = createInputWireArray(siSHA256HexStr.length()/2);
                keyEncWires = createInputWireArray(keyEncStr.length()/2);
                ivLast3rdBlockWires = createInputWireArray(ivLast3rdBlockHexStr.length()/2);
                plaintextInlast3rdBlockWires = createInputWireArray(plaintextInlast3rdBlockStr.length()/2);


                Wire[] digest = new SHA256DECOGadget(inputWires, 8,siSHA256Wires, 8, inputWires.length,false, true,previousLens,"").getOutputWires();
                Wire[] digestBits = new WireArray(digest).getBits(32).asArray();
                Wire[] hInput = new Wire[96];
                for (int i = 0; i < 32; i++) {
                    hInput[i] = keyMacWires[i].xorBitwise(generator.createConstantWire(0x5c), 8);
                }

                Arrays.fill(hInput,32,64,generator.createConstantWire(0x5c));

                Wire[] tmp;
                for (int i = 0; i < 32; i++) {
                    if (i % 4 == 0) {
                        tmp = Arrays.copyOfRange(digestBits, i * 8+3*8,(i + 1) * 8+3*8);
                    }
                    else if (i % 4 == 1) {
                        tmp = Arrays.copyOfRange(digestBits, i * 8+1*8,(i + 1) * 8+1*8);
                    }
                    else if (i % 4 == 2) {
                        tmp = Arrays.copyOfRange(digestBits, i * 8-8,(i + 1) * 8-8);
                    }
                    else  {
                        tmp = Arrays.copyOfRange(digestBits, i * 8-3*8,(i + 1) * 8-3*8);
                    }
                    hInput[i+64] = new WireArray(tmp).packAsBits(8);
                }

                Wire[] mac = new SHA256Gadget(hInput, 8, 96, false, true, "").getOutputWires();
                Wire[] macBits = new WireArray(mac).getBits(32).asArray();

                Wire[] aesInput = new Wire[32];
                for (int i = 0; i < 32; i++) {
                    if (i % 4 == 0) {
                        tmp = Arrays.copyOfRange(macBits, i * 8+3*8,(i + 1) * 8+3*8);
                    }
                    else if (i % 4 == 1) {
                        tmp = Arrays.copyOfRange(macBits, i * 8+1*8,(i + 1) * 8+1*8);
                    }
                    else if (i % 4 == 2) {
                        tmp = Arrays.copyOfRange(macBits, i * 8-8,(i + 1) * 8-8);
                    }
                    else  {
                        tmp = Arrays.copyOfRange(macBits, i * 8-3*8,(i + 1) * 8-3*8);
                    }
                    aesInput[i] = new WireArray(tmp).packAsBits(8);
                }

                final int bitPerWire = 8;
                Wire[] plaintext = new Wire[48];
                int lengthOfPlaintextInLast3rdBlock =  16 - paddingWires.length;
                int count = 0;
                if (lengthOfPlaintextInLast3rdBlock != 0) {
                    for (int i = 0; i < lengthOfPlaintextInLast3rdBlock; i++ ) {
                        plaintext[count++] = generator.createConstantWire(
                                Integer.valueOf(plaintextInlast3rdBlockStr.substring(i*2, (i+1)*2),16));
                    }
                }

                for (int i = 0; i < 32; i++) {
                    plaintext[count++] = aesInput[i];
                }

                for (int i =0; i < paddingWires.length; i++) {
                    plaintext[count++] = generator.createConstantWire(Integer.valueOf(paddingStr.substring(i*2,i*2+2),16));
                }

                digest = new AES128CBCGadget(plaintext, keyEncWires, ivLast3rdBlockWires, bitPerWire, false,
                        "AES128CBC",  "").getOutputWires();
                makeOutputArray(digest);
            }

            @Override
            public void generateSampleInput(CircuitEvaluator e) {
                for (int i = 0; i < inputStr.length()/2; i++) {
                    e.setWireValue(inputWires[i], Integer.valueOf(inputStr.substring(i*2,i*2+2),16));
                }
                for (int i = 0; i < siSHA256HexStr.length()/2; i++ ) {
                    e.setWireValue(siSHA256Wires[i], Integer.valueOf(siSHA256HexStr.substring(i*2,i*2+2), 16));
                }
                for (int i = 0; i < keyMacStr.length()/2; i++) {
                    e.setWireValue(keyMacWires[i], Integer.valueOf(keyMacStr.substring(i*2, i*2+2),16));
                }
                for (int i = 0; i < paddingStr.length()/2; i++) {
                    e.setWireValue(paddingWires[i], Integer.valueOf(paddingStr.substring(i*2, i*2+2),16));
                }
                for (int i = 0; i < keyEncStr.length()/2; i++) {
                    e.setWireValue(keyEncWires[i], Integer.valueOf(keyEncStr.substring(i*2, i*2+2),16));
                }
                for (int i = 0; i < ivLast3rdBlockHexStr.length()/2; i++ ) {
                    e.setWireValue(ivLast3rdBlockWires[i], Integer.valueOf(ivLast3rdBlockHexStr.substring(i*2,i*2+2), 16));
                }

                if (plaintextInlast3rdBlockStr.length() != 0) {
                    for (int i = 0; i < plaintextInlast3rdBlockStr.length()/2; i++) {
                        e.setWireValue(plaintextInlast3rdBlockWires[i], Integer.valueOf(plaintextInlast3rdBlockStr.substring(i*2, i*2+2),16));
                    }
                }


            }
        };

        generator.generateCircuit();
        generator.evalCircuit();
        CircuitEvaluator evaluator = generator.getCircuitEvaluator();

        String outDigest = "";
        for (Wire w : generator.getOutWires()) {
            outDigest += Util.padZeros(evaluator.getWireValue(w).toString(16), 2);
        }
        assertEquals(outDigest, expectedDigestStr);
    }
}
