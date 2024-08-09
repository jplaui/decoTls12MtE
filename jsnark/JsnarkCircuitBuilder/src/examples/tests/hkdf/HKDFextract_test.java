package examples.tests.hkdf;

import util.Util;
import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import examples.gadgets.hkdf.HKDFextractGadget;
import junit.framework.TestCase;
import java.util.logging.Logger;

public class HKDFextract_test extends TestCase {

    public void testCase1(){
        // First Extract in TLS 1.3 for 1-RTT without PSK, 0 is Salt and 0 is IKM (with pre-shared secret: IKM = PSK)
        // ES = 33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a

        String inputSalt = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        String inputIKM = "0000000000000000000000000000000000000000000000000000000000000000";

        Boolean paddingRequired = true; // Key requires padding

        String expectedDigest = "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a";

        CircuitGenerator generator = new CircuitGenerator("HMACGenerator_Test1") {
            
            private Wire[] inputSaltWire;
            private Wire[] inputIKMWire;    
            
            @Override
			protected void buildCircuit() {
                // Public input wire
				inputSaltWire = createInputWireArray(inputSalt.length()/2);
                // Private witness wire
                inputIKMWire = createInputWireArray(inputIKM.length()/2);

                // Run HMAC
				Wire[] digest = new HKDFextractGadget(inputSaltWire, inputIKMWire).getOutputWires();
                makeOutputArray(digest);
            }

            @Override
			public void generateSampleInput(CircuitEvaluator e) {              
				for (int i = 0; i < inputSalt.length()/2; i++) {
					e.setWireValue(inputSaltWire[i], Integer.valueOf(inputSalt.substring(i*2, i*2+2),16));
				}
                for (int i = 0; i < inputIKM.length()/2; i++) {
					e.setWireValue(inputIKMWire[i], Integer.valueOf(inputIKM.substring(i*2, i*2+2),16));
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

        assertEquals(expectedDigest, outDigest);
    }
}
