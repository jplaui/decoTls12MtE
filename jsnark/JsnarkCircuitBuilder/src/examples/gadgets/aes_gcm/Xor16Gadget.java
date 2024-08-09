package examples.gadgets.aes_gcm;

import java.math.BigInteger;
import circuit.operations.Gadget;
import circuit.structure.Wire;
import circuit.structure.WireArray;


public class Xor16Gadget extends Gadget {

	private Wire[] inp1;
	private Wire[] inp2;
	private Wire[] xor;

	public Xor16Gadget(Wire[] inp1, Wire[] inp2, String... desc) {
		super(desc);
		this.inp1 = inp1;
		this.inp2 = inp2;
		buildCircuit();
	}

	private void buildCircuit() {
		
		if (inp1.length != inp2.length) {
			throw new IllegalArgumentException();
		}

		xor = new Wire[16];
		for (int i = 0; i < inp1.length; i++) {
			xor[i] = inp1[i].getBitWires(8).xorWireArray(inp2[i].getBitWires(8)).packAsBits();
			//xor[i] = inp1[i].xor(inp2[i]);
		}
	}

	@Override
	public Wire[] getOutputWires() {
		return xor;
	}
}
