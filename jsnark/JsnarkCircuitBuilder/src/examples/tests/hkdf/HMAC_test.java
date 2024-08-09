package examples.tests.hkdf;

import util.Util;
import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import examples.gadgets.hkdf.HMACGadget;
import junit.framework.TestCase;
import java.util.logging.Logger;

public class HMAC_test extends TestCase {

    private final static Logger LOGGER = Logger.getLogger(HMAC_test.class.getName());
    // LOGGER.info(String.valueOf(generator.getNumOfConstraints()));
    
    // @Test
    public void testCase1(){

        // String inputString = "0000000000000000000000000000000000000000000000000000000000000000"; 
        // This is "Test"
        String inputString = "54657374"; 
        // Dummy key of length 64 byte (128/2)
        String secretKey = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"; 
        // String expectedDigest = "b49c55769c253ee539416ceea6ea72f77016027635688119348d7f99b9622719";

        String expectedDigest = "b84a269128e6a85c693b2371816ba0bb21a2da2bab2b935e37fd8d93d022db6a";
        
        CircuitGenerator generator = new CircuitGenerator("HMACGenerator_Test1") {
            
            private Wire[] inputTextWire;
            private Wire[] inputSecretWire;          
            
            @Override
			protected void buildCircuit() {
                System.out.println(inputString.length());
                
                // Public input wire
				inputTextWire = createInputWireArray(inputString.length()/2);
                // Private witness wire
                inputSecretWire = createProverWitnessWireArray(secretKey.length()/2);

                // Run HMAC
				Wire[] digest = new HMACGadget(inputTextWire, inputSecretWire, false).getOutputWires();
				makeOutputArray(digest);
			}

            @Override
			public void generateSampleInput(CircuitEvaluator e) {              
				for (int i = 0; i < inputString.length()/2; i++) {
					e.setWireValue(inputTextWire[i], Integer.valueOf(inputString.substring(i*2, i*2+2),16));
				}
                for (int i = 0; i < secretKey.length()/2; i++) {
					e.setWireValue(inputSecretWire[i], Integer.valueOf(secretKey.substring(i*2, i*2+2),16));
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
