package examples.gadgets.aes_gcm;

import circuit.operations.Gadget;
import circuit.structure.Wire;
import examples.gadgets.blockciphers.AES128CipherGadget;


public class AES128WrapperGadget extends Gadget {

	private Wire[] msg;
	private Wire[] key;
	private Wire[] ciphertext;

	public AES128WrapperGadget(Wire[] msg, Wire[] key, String... desc) {
		super(desc);
		this.msg = msg;
		this.key = key;
		buildCircuit();
	}

	private void buildCircuit() {
		
		Wire[] expandedKey = AES128CipherGadget.expandKey(key);
		ciphertext = new AES128CipherGadget(msg, expandedKey).getOutputWires();
	}

	@Override
	public Wire[] getOutputWires() {
		return ciphertext;
	}
}

