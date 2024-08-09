// This implements HKDF extract given an HMAC using a SHA-256 hash function

package examples.gadgets.hkdf;

import circuit.operations.Gadget;
import circuit.structure.Wire;

import examples.gadgets.hkdf.HMACGadget;
import java.util.Arrays;

public class HKDFexpandLabelGadget extends Gadget {

    // Expand label takes secret, label, context and length
    private Wire[] secret;
    private Wire[] label;
    private Wire[] context;
    private int lenKey;
    private Wire[] lenKeyWire;
    private Wire[] tlsWire; 
    private Wire[] hkdfLabel; 
    
    private int hashLen = 32; // SHA-256 has 32 byte output / 32 octets
    private int N;
    private Wire[] output;

    

    public HKDFexpandLabelGadget(Wire[] secret, Wire[] label, Wire[] context, Wire[] tlsString, String lenKeyStr, String... desc) {
        
        // Derive-Secret(Secret, Label, Messages) = HKDF-Expand-Label(Secret, Label, context = Transcript-Hash(Messages), Hash.length)
        super(desc);
        this.secret = secret;
        this.label = label;
        this.context = context;
        
        this.tlsWire = tlsString;

        this.lenKey = Integer.parseInt(lenKeyStr, 16);

        // Convert Bytestring to wire
        int lenKeyLength = lenKeyStr.length()/2;
        Wire[] lenKeyWiretmp = new Wire[lenKeyLength];
        for (int i = 0; i < lenKeyLength; i++) {
            lenKeyWiretmp[i] = generator.createConstantWire(Integer.valueOf(lenKeyStr.substring(i*2,i*2+2),16));
        }
        this.lenKeyWire = lenKeyWiretmp;
        
        // Pre-Processing: HKDF-Expand Label -> HKDF Expand
        // Concatenation: 2 byte length, 7 to 255 byte label, 0 to 255 byte context, total length 9 to 514 byte
        // label: "tls13 " 6 byte + label bytestring
        processLabel();
        
        // pseudorandom key of at least HashLen octets
        if (this.secret.length < this.hashLen) {
			throw new IllegalArgumentException("Length of prk must be at least of size hashLen.");
		}

//        if (this.lenKey > 255*this.hashLen) {
//            throw new IllegalArgumentException("Length of output is too long, must be max 255*hashLen");
//        }

        // N = ceil(L/HashLen), In our case this is always 1
        this.N = (int) Math.ceil(this.lenKey * 1.0/ this.hashLen);
        
        // Build the circuit
        buildCircuit();
    }

    protected void buildCircuit() {

        // This is HKDF Expand
        // Initialize correct length T wire
        Wire[] tempWire = new Wire[this.hkdfLabel.length+1];

        System.arraycopy(this.hkdfLabel, 0, tempWire, 0, this.hkdfLabel.length);
        Arrays.fill(tempWire, this.hkdfLabel.length, this.hkdfLabel.length+1, generator.createConstantWire(0x01));

        // HMAC(secret, hkdfLabel, lenghth) (length is anyways 32, padding required as secret is only 32 Byte)
        Wire[] okm = new HMACGadget(tempWire, this.secret, true, "").getOutputWires();


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

    public String convertASCIIStringToHexString(String asciiStr) {
        char[] ch = asciiStr.toCharArray();

        StringBuilder builder = new StringBuilder();

        for (char c : ch) {
            int i = (int) c;
            builder.append(Integer.toHexString(i).toUpperCase());
        }

        return  builder.toString();
    }

    private void processLabel() {

        int lengthTransform = this.label.length + this.context.length + this.lenKeyWire.length + this.tlsWire.length;
        Wire[] transformedLabel = new Wire[lengthTransform];

        // Append length || "tls13 " + label || context 
        System.arraycopy(this.lenKeyWire, 0, transformedLabel, 0, this.lenKeyWire.length);
        System.arraycopy(this.tlsWire, 0, transformedLabel, this.lenKeyWire.length, this.tlsWire.length);
        System.arraycopy(this.label, 0, transformedLabel, this.lenKeyWire.length+this.tlsWire.length, this.label.length);
        System.arraycopy(this.context, 0, transformedLabel, this.lenKeyWire.length+this.tlsWire.length+this.label.length, this.context.length);

        this.hkdfLabel = transformedLabel;
    }

    @Override
	public Wire[] getOutputWires() {
		return output;
	}
}
