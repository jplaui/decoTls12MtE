// This implements HKDF extract given an HMAC using a SHA-256 hash function

package examples.gadgets.hkdf;

import util.Util;
import circuit.operations.Gadget;
import circuit.structure.Wire;
import circuit.structure.WireArray;

import examples.gadgets.hkdf.HMACGadget;
import java.util.Arrays;

public class HKDFextractGadget extends Gadget {

    // HMAC takes as input the text and a secret Key 
    private Wire[] salt;
    private Wire[] IKM;
    private int hashLen = 32; // SHA-256 has 32 byte output / 32 octets

    //  Output Wire
    private Wire[] output;

    public HKDFextractGadget(Wire[] salt, Wire[] IKM, String... desc) {

        super(desc);

        // The first input value to HMAC is the key, hence the salt
        this.salt = salt;
        // The second input to HMAC is the "input", hence IKM
        this.IKM = IKM;

        // Constraint: If no salt value is provided, the salt value is set to hashLen zeros
        if (this.IKM.length % hashLen != 0) {
			throw new IllegalArgumentException("Salt needs to be provided as 32 Byte random input. If none, initialize as 32 Byte of 0x00.");
		}
        
        // Build the circuit
        buildCircuit();
    }

    protected void buildCircuit() {
        // Compute the Hash, key = salt, input = IKM, key always requires padding for HMAC as its only 32 byte by default
        Wire[] prk = new HMACGadget(IKM, salt, true, "").getOutputWires();
        output = prk;
    }

    @Override
	public Wire[] getOutputWires() {
		return output;
	}
}
