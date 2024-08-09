package examples.tests.hash;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import examples.gadgets.hash.SHA256DECOGadget;
import junit.framework.TestCase;
import util.Util;


public class SHA256DECOGenerator_Test extends TestCase {
    public void testCase1(){
        String inputStr = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        String ivHexStr = "6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19";
        String expectedDigest = "da5698be17b9b46962335799779fbeca8ce5d491c0d26243bafef9ea1837a9d8";

        CircuitGenerator generator = new CircuitGenerator("SHA256DECOGenerator_Test1") {

            Wire[] inputWires;

            Wire[] ivWires;
            @Override
            protected void buildCircuit() {
                inputWires = createInputWireArray(inputStr.length()/2);
                ivWires = createInputWireArray(ivHexStr.length()/2);
                Wire[] digest = new SHA256DECOGadget(inputWires, 8,ivWires, 8, 64,
                        false, false,0,"").getOutputWires();
                makeOutputArray(digest);
            }

            @Override
            public void generateSampleInput(CircuitEvaluator e) {
                for (int i = 0; i < inputStr.length()/2; i++) {
                    e.setWireValue(inputWires[i], Integer.valueOf(inputStr.substring(i*2,i*2+2),16));
                }
                for (int i = 0; i < ivHexStr.length()/2; i++ ) {
                    e.setWireValue(ivWires[i], Integer.valueOf(ivHexStr.substring(i*2,i*2+2), 16));
                }
            }
        };

        generator.generateCircuit();
        generator.evalCircuit();
        CircuitEvaluator evaluator = generator.getCircuitEvaluator();

        String outDigest = "";
        for (Wire w : generator.getOutWires()) {
            outDigest += Util.padZeros(evaluator.getWireValue(w).toString(16), 8);
        }
        assertEquals(outDigest, expectedDigest);
    }

    //SHA256 test for 1024bits withut padding
    public void testCase2(){
        String inputStr = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
        String ivHexStr = "6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19";
        String expectedDigest = "89d03c12e077467125c82a22aa7bf90353dcd4f6e9520159bd830150d0d16272";

        CircuitGenerator generator = new CircuitGenerator("SHA256DECOGenerator_Test2") {

            Wire[] inputWires;

            Wire[] ivWires;
            @Override
            protected void buildCircuit() {
                inputWires = createInputWireArray(inputStr.length()/2);
                ivWires = createInputWireArray(ivHexStr.length()/2);
                Wire[] digest = new SHA256DECOGadget(inputWires, 8,ivWires, 8,
                        64*2,false, false,0,"").getOutputWires();
                makeOutputArray(digest);
            }

            @Override
            public void generateSampleInput(CircuitEvaluator e) {
                for (int i = 0; i < inputStr.length()/2; i++) {
                    e.setWireValue(inputWires[i], Integer.valueOf(inputStr.substring(i*2,i*2+2),16));
                }
                for (int i = 0; i < ivHexStr.length()/2; i++ ) {
                    e.setWireValue(ivWires[i], Integer.valueOf(ivHexStr.substring(i*2,i*2+2), 16));
                }
            }
        };

        generator.generateCircuit();
        generator.evalCircuit();
        CircuitEvaluator evaluator = generator.getCircuitEvaluator();

        String outDigest = "";
        for (Wire w : generator.getOutWires()) {
            outDigest += Util.padZeros(evaluator.getWireValue(w).toString(16), 8);
        }
        assertEquals(outDigest, expectedDigest);
    }

    public void testCase3(){
        String inputStr = "54222c22706572736f6e616c2064617461223a7b22616765223a223230227d2c227072696365223a33383030302c2274696d65223a2231323a30303a3030222c22766f6c756d65223a3332313635347d";
        String ivHexStr = "d295c257c747f7e9804731ede456046c617e9148ac37ce11a9f335ed5f9c5e0a";
        String expectedDigest = "55324caf1ba85789abb2029508e4fbd236a62e4e73edb10e24e6b77310afd7b5";

        CircuitGenerator generator = new CircuitGenerator("SHA256DECOGenerator_Test3") {

            Wire[] inputWires;

            Wire[] ivWires;
            @Override
            protected void buildCircuit() {
                inputWires = createInputWireArray(inputStr.length()/2);
                ivWires = createInputWireArray(ivHexStr.length()/2);
                Wire[] digest = new SHA256DECOGadget(inputWires, 8,ivWires, 8,80
                        ,false, true,128,"").getOutputWires();
                makeOutputArray(digest);
            }

            @Override
            public void generateSampleInput(CircuitEvaluator e) {
                for (int i = 0; i < inputStr.length()/2; i++) {
                    e.setWireValue(inputWires[i], Integer.valueOf(inputStr.substring(i*2,i*2+2),16));
                }
                for (int i = 0; i < ivHexStr.length()/2; i++ ) {
                    e.setWireValue(ivWires[i], Integer.valueOf(ivHexStr.substring(i*2,i*2+2), 16));
                }
            }
        };

        generator.generateCircuit();
        generator.evalCircuit();
        CircuitEvaluator evaluator = generator.getCircuitEvaluator();

        String outDigest = "";
        for (Wire w : generator.getOutWires()) {
            outDigest += Util.padZeros(evaluator.getWireValue(w).toString(16), 8);
        }
        assertEquals(outDigest, expectedDigest);
    }

    public void testCase4(){
        String inputStr = "54222c22706572736f6e616c2064617461223a7b22616765223a223230227d2c227072696365223a33383030302c2274696d65223a2231323a30303a3030222c22766f6c756d65223a3332313635347d";
        String ivHexStr = "d295c257c747f7e9804731ede456046c617e9148ac37ce11a9f335ed5f9c5e0a";
        String expectedDigest = "55324caf1ba85789abb2029508e4fbd236a62e4e73edb10e24e6b77310afd7b5";

        CircuitGenerator generator = new CircuitGenerator("SHA256DECOGenerator_Test3") {

            Wire[] inputWires;

            Wire[] ivWires;
            @Override
            protected void buildCircuit() {
                inputWires = createInputWireArray(inputStr.length()/2);
                ivWires = createInputWireArray(ivHexStr.length()/2);
                Wire[] digest = new SHA256DECOGadget(inputWires, 8,ivWires, 8,80
                        ,false, true,128,"").getOutputWires();
                makeOutputArray(digest);
            }

            @Override
            public void generateSampleInput(CircuitEvaluator e) {
                for (int i = 0; i < inputStr.length()/2; i++) {
                    e.setWireValue(inputWires[i], Integer.valueOf(inputStr.substring(i*2,i*2+2),16));
                }
                for (int i = 0; i < ivHexStr.length()/2; i++ ) {
                    e.setWireValue(ivWires[i], Integer.valueOf(ivHexStr.substring(i*2,i*2+2), 16));
                }
            }
        };

        generator.generateCircuit();
        generator.evalCircuit();
        CircuitEvaluator evaluator = generator.getCircuitEvaluator();

        String outDigest = "";
        for (Wire w : generator.getOutWires()) {
            outDigest += Util.padZeros(evaluator.getWireValue(w).toString(16), 8);
        }
        assertEquals(outDigest, expectedDigest);
    }


}
