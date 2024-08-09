package examples.generators.aes_gcm;

import circuit.config.Config;
import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import examples.gadgets.aes_gcm.AES128WrapperGadget;
//import examples.gadgets.blockciphers.AES128CipherGadget;


// A sample usage of the AES128 CBC gadget
public class TagMaskCipherCircuitGenerator  extends CircuitGenerator {

	//private Wire[] plaintext;
	private Wire[] key;
	private Wire[] iv_counter;
	private Wire[] ciphertext;

	//private AES128WrapperGadget gadget;

	public TagMaskCipherCircuitGenerator(String circuitName) {
	super(circuitName);
	}

	@Override
	protected void buildCircuit() {
		key = createProverWitnessWireArray(16);
		iv_counter = createInputWireArray(16);
		ciphertext = new AES128WrapperGadget(iv_counter, key, "AES128Wrapper").getOutputWires();
		makeOutputArray(ciphertext);
		for (Wire c : ciphertext) {
			makeOutput(c);
		}

	}

	@Override
	public void generateSampleInput(CircuitEvaluator circuitEvaluator) {

		String keyHexStr = "7fddb57453c241d03efbed3ac44e371c";
		String ivctrHexStr = "ee283a3fc75575e33efd488700000001";	
		// result is cipher tag= "598d3ea40503b2563c8843964ff8125b";

		for (int i = 0; i < key.length; i++) {
			circuitEvaluator.setWireValue(key[i], Integer.valueOf(keyHexStr.substring(i*2,i*2+2), 16));
		}
		for (int i = 0; i < iv_counter.length; i++) {
			circuitEvaluator.setWireValue(iv_counter[i], Integer.valueOf(ivctrHexStr.substring(i*2,i*2+2), 16));
		}
	}

	public static void main(String[] args) throws Exception {

		Config.hexOutputEnabled = true;
		TagMaskCipherCircuitGenerator generator = new TagMaskCipherCircuitGenerator(
			"GCMTagMaskCipher_Circuit");
		generator.generateCircuit();
		generator.evalCircuit();
		generator.prepFiles();
		generator.runLibsnark();

	}
}




