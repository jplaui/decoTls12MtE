package examples.tests.hkdf;

import util.Util;
import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import examples.gadgets.hkdf.HKDFexpandLabelGadget;
import junit.framework.TestCase;
import java.util.logging.Logger;

public class HKDFExpandLabel_test extends TestCase {

    public void testCase1(){
        // For dES, Expand function takes as an input the H_0 = H("") and the byte version of Label3 = "derived"
        // Derive-Secret(Secret = ES, Label = Label3, Messages = H_0)
        // dES is the expected digest of HKDF Expand(ES, Label3, H_0) 
        
        
        // ES
        String secret = "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a";
        // Label
        String infoStr = "derived ";
        String infoHexString = convertASCIIStringToHexString(infoStr);
        // String infoHexString = "64657269766564";   
        // SHA-256 of an empty string (This is already Transcript-Hash(message) = context for our case where "")
        String contextString = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        int lenKey = 32;
        // 0020 big endian uint16, should be passed as 2B string
        // String lenKeyString = Integer.toHexString(lenKey);
        String lenKeyString = "00200D";
        

        String tlsString = "tls13 ";
        String tlsHexString = convertASCIIStringToHexString(tlsString);

        
        // dES
        String expectedDigest = "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba";
        // Boolean paddingRequired = true; // Key requires padding

        CircuitGenerator generator = new CircuitGenerator("HMACGenerator_Test1") {
            
            private Wire[] secretWire;
            private Wire[] labelWire; 
            private Wire[] contextWire;         
            private Wire[] tlsWire;      
            
            @Override
            protected void buildCircuit() {
                System.out.println(lenKeyString);
                // Private witness wire
                secretWire = createProverWitnessWireArray(secret.length()/2);
                // Public input wires
				labelWire = createInputWireArray(infoHexString.length()/2);
                contextWire = createInputWireArray(contextString.length()/2);
                tlsWire = createInputWireArray(tlsHexString.length()/2);

                // Run HKDFexpandLabelGadget
				Wire[] digest = new HKDFexpandLabelGadget(secretWire, labelWire, contextWire, tlsWire, lenKeyString, "").getOutputWires();
				makeOutputArray(digest);
            }

            @Override
			public void generateSampleInput(CircuitEvaluator e) {      
                
                
                for (int i = 0; i < secret.length()/2; i++) {
					e.setWireValue(secretWire[i], Integer.valueOf(secret.substring(i*2, i*2+2),16));
				}
                for (int i = 0; i < infoHexString.length()/2; i++) {
					e.setWireValue(labelWire[i], Integer.valueOf(infoHexString.substring(i*2, i*2+2),16));
				}
                for (int i = 0; i < contextString.length()/2; i++) {
					e.setWireValue(contextWire[i], Integer.valueOf(contextString.substring(i*2, i*2+2),16));
				}
                for (int i = 0; i < tlsHexString.length()/2; i++) {
                    e.setWireValue(tlsWire[i], Integer.valueOf(tlsHexString.substring(i*2, i*2+2),16));
                }
                
			}
        };

        generator.generateCircuit();
		generator.evalCircuit();
		CircuitEvaluator evaluator = generator.getCircuitEvaluator();

        String outDigest = "";
		for (Wire w : generator.getOutWires()) {
			// outDigest += Util.padZeros(evaluator.getWireValue(w).toString(16), 8);
            outDigest += Util.padZeros(evaluator.getWireValue(w).toString(16),8);
		}

        assertEquals(expectedDigest, outDigest);
    }

    public String convertASCIIStringToHexString(String asciiStr) {
        char[] ch = asciiStr.toCharArray();

        StringBuilder builder = new StringBuilder();

        for (char c : ch) {
            int i = (int) c;

            builder.append(Integer.toHexString(i).toUpperCase());
        }

        return  builder.toString();
    }
}
