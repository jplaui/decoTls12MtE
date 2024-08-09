package examples.tests.blockciphers;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import examples.gadgets.blockciphers.AES128CBCGadget;
import junit.framework.TestCase;
import org.junit.Test;
import util.Util;


import java.util.ArrayList;


public class AES128CBC_Test extends TestCase {

    @Test
    public void testCase1() {
        CircuitGenerator generator = new CircuitGenerator("AES128CBC_Test1") {

            private Wire[] plaintext; // 16 bytes
            private Wire[] key; // 16 bytes

            private Wire[] iv;
            private Wire[] ciphertext; // 16 bytes

            @Override
            protected void buildCircuit() {
                int bitPerWire = 8;
                plaintext = createInputWireArray(48);
                key = createInputWireArray(16);
                iv = createInputWireArray(16);
                ciphertext = new AES128CBCGadget(plaintext, key, iv, bitPerWire, false,
                        "AES128CBC",  "").getOutputWires();
                makeOutputArray(ciphertext);
            }

            @Override
            public void generateSampleInput(CircuitEvaluator evaluator) {

                String ivHexStr = "0f0afcdda0bd0ef8d782ecdccdec3ca5";
                String keyHexStr = "b8d197b1d979c0c9e4a8427ba2da2d0b";
                String msgHexStr = "35347d335b3fd69267475869a349cfeac40ebe79de22a45d6b26cce45a6c52836dde2b0c0c0c0c0c0c0c0c0c0c0c0c0c";


                for (int i = 0; i < plaintext.length; i++) {
                    evaluator.setWireValue(plaintext[i], Integer.valueOf(msgHexStr.substring(i*2,i*2+2), 16));
                }
                for (int i = 0; i < key.length; i++) {
                    evaluator.setWireValue(key[i], Integer.valueOf(keyHexStr.substring(i*2,i*2+2), 16));
                }

                for (int i = 0; i < iv.length; i++ ) {
                    evaluator.setWireValue(iv[i], Integer.valueOf(ivHexStr.substring(i*2,i*2+2), 16));
                }
            }

        };
        generator.generateCircuit();
        generator.evalCircuit();
        CircuitEvaluator evaluator = generator.getCircuitEvaluator();
        ArrayList<Wire> cipherText = generator.getOutWires();

        String resultString = "680b7af1e5c7b0d45545d8f8b6ae661f998d564713b4cd319a5bacc71c36ae34a860babbb10b104b133ac06480bca198";
        String outDigest = "";
        for (Wire w : generator.getOutWires()) {
            outDigest += Util.padZeros(evaluator.getWireValue(w).toString(16), 2);
        }

        assertEquals(outDigest, resultString);
    }

}
