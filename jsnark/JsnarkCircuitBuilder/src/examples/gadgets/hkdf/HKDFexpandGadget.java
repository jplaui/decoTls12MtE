package examples.gadgets.hkdf;
import circuit.operations.Gadget;
import circuit.structure.Wire;

import examples.gadgets.hkdf.HMACGadget;
import java.util.Arrays;

public class HKDFexpandGadget extends Gadget {

    // Expand label takes secret, label, context and length
    private Wire[] secretWire;
    private Wire[] infoWire;
    private int lenKey;
    private Wire[] lenKeyWire;
    
    private int hashLen = 32; // SHA-256 has 32 byte output / 32 octets
    private int N;
    private Wire[] output;


    public HKDFexpandGadget(Wire[] secret, Wire[] info, String lenKeyStr, String... desc) {
        // Derive-Secret(Secret, Label, Messages) = HKDF-Expand-Label(Secret, Label, context = Transcript-Hash(Messages), Hash.length)
        super(desc);
        this.secretWire = secret;
        this.infoWire = info;

        this.lenKey = Integer.parseInt(lenKeyStr, 16);

        // Convert Bytestring to wire
        int lenKeyLength = lenKeyStr.length()/2;
        Wire[] lenKeyWiretmp = new Wire[lenKeyLength];
        for (int i = 0; i < lenKeyLength; i++) {
            lenKeyWiretmp[i] = generator.createConstantWire(Integer.valueOf(lenKeyStr.substring(i*2,i*2+2),16));
        }
        this.lenKeyWire = lenKeyWiretmp;
        
        
        // pseudorandom key of at least HashLen octets
        if (this.secretWire.length < this.hashLen) {
            throw new IllegalArgumentException("Length of prk must be at least of size hashLen.");
        }

        if (this.lenKey > 255*this.hashLen) {
            throw new IllegalArgumentException("Length of output is too long, must be max 255*hashLen");
        }

        // N = ceil(L/HashLen), In our case this is always 1
        this.N = (int) Math.ceil(this.lenKey * 1.0/ this.hashLen);
        
        // Build the circuit
        buildCircuit();
    }

    protected void buildCircuit() {

        // This is HKDF Expand
        // Initialize correct length T wire
        Wire[] tempWire = new Wire[this.infoWire.length+1];

        System.arraycopy(this.infoWire, 0, tempWire, 0, this.infoWire.length);
        Arrays.fill(tempWire, this.infoWire.length, this.infoWire.length+1, generator.createConstantWire(0x01));

        // HMAC(secret, hkdfLabel, lenghth) (length is anyways 32, padding required as secret is only 32 Byte)
        Wire[] okm = new HMACGadget(tempWire, this.secretWire, true, "").getOutputWires();


        // ------------------------------------ Version that appends empty string
        // T_0 || info ||  0x01
        // Wire[] TWire = new Wire[hashLen]; // 32 Byte, only first hash computation is necessary
        // TWire[0] = generator.createConstantWire(0x00);
        // Wire[] tempWire = new Wire[this.hkdfLabel.length+2];
        // // String zeroString = " "; // If empty length 0, cannot be converted to ASCII
        // // Wire[] TWiretemp = new Wire[1];
        // // for (int i = 0; i < 1; i++) {
        // //     TWiretemp[i] = generator.createConstantWire(Integer.valueOf(convertASCIIStringToHexString(zeroString),16));
        // // }
        // // TWire[0] = TWiretemp[0];
        // System.arraycopy(TWire, 0, tempWire, 0, 1);
        // System.arraycopy(this.hkdfLabel, 0, tempWire, 1, this.hkdfLabel.length);
        // Arrays.fill(tempWire, this.hkdfLabel.length+1, this.hkdfLabel.length+2, generator.createConstantWire(0x01));
        // Wire[] okm = new HMACGadget(tempWire, this.secret, true, "").getOutputWires();
        // ------------------------------------
        

        // Output: OKM = first L octets of T = T(1)
        output = okm;
    }

    @Override
	public Wire[] getOutputWires() {
		return output;
	}

}

