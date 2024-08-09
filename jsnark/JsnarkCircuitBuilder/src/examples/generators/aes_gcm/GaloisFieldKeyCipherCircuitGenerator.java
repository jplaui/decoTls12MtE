package examples.generators.aes_gcm;

import java.math.BigInteger;
import circuit.config.Config;
import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import examples.gadgets.aes_gcm.AES128WrapperGadget;
//import examples.gadgets.blockciphers.AES128CipherGadget;


// A sample usage of the AES128 CBC gadget
public class GaloisFieldKeyCipherCircuitGenerator extends CircuitGenerator {

	//private Wire[] plaintext;
	private Wire[] key;
	private Wire[] msg;
	private Wire[] ciphertext;

	//private AES128WrapperGadget gadget;

	public GaloisFieldKeyCipherCircuitGenerator(String circuitName) {
	super(circuitName);
	}

	@Override
	protected void buildCircuit() {

		// msg is an all zeros vector of 16 bytes
		msg = createInputWireArray(16);
		key = createProverWitnessWireArray(16);
		ciphertext = new AES128WrapperGadget(msg, key, "AES128Wrapper").getOutputWires();
		makeOutputArray(ciphertext);
		for (Wire c : ciphertext) {
		    makeOutput(c);
		}

	}

	@Override
	public void generateSampleInput(CircuitEvaluator circuitEvaluator) {

		String keyHexStr = "7fddb57453c241d03efbed3ac44e371c";
		// expected output = "122204f9d2a456649d2bb1f744c939d9";

		for (int i = 0; i < msg.length; i++) {
			circuitEvaluator.setWireValue(msg[i], BigInteger.ZERO );
		}
		for (int i = 0; i < key.length; i++) {
			//circuitEvaluator.setWireValue(key[i], Integer.valueOf(keyHexStr.substring(i*2,i*2+2), 16));
			circuitEvaluator.setWireValue(key[i], Integer.valueOf(keyHexStr.substring(i*2,i*2+2), 16));
		}
	}

	public static void main(String[] args) throws Exception {

		Config.hexOutputEnabled = true;
		GaloisFieldKeyCipherCircuitGenerator generator = new GaloisFieldKeyCipherCircuitGenerator(
			"GCMKeyCipher_Circuit");
		generator.generateCircuit();
		generator.evalCircuit();
		generator.prepFiles();
		generator.runLibsnark();

	}
}

