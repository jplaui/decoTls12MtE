package examples.gadgets.hkdf;

import util.Util;
import circuit.operations.Gadget;
import circuit.structure.Wire;
import circuit.structure.WireArray;

import examples.gadgets.hash.SHA256Gadget;
import java.util.Arrays;

public class HMACGadget extends Gadget {
    
    // HMAC takes as input the text and a secret Key 
    private Wire[] plainText;
	private Wire[] secretKey;
    private int plainTextLen;
    private int keyLen;
    private int B = 64; // B = 64 byte for SHA-256 in HMAC

    private int numBlocks;
    private Wire[] preparedInputBits;
    private boolean paddingRequired;
    private int bitwidthPerInputElement = 8;
    //  Output Wire
    private Wire[] output;
    // private int diffBits;
   
	public HMACGadget(Wire[] text, Wire[] key, Boolean paddingRequired, String... desc) {

        super(desc);

        this.plainText = text;
        this.secretKey = key;
        this.paddingRequired = paddingRequired;

        if (!paddingRequired && this.secretKey.length % 64 != 0) {
			throw new IllegalArgumentException("When padding is not forced, totalLengthInBytes % 64 must be zero.");
		}
        
        // Build the circuit
        buildCircuit();
    }


    protected void buildCircuit() {

        // Pad 0x00 to key to make it 64 Byte as required in HMAC
        prepare();
        
        // Inner Hash Wire Definition
        Wire[] hInner = new Wire[B+this.plainText.length]; // 64 + length of input text (4) = 68
        Wire[] hOuter = new Wire[B+32]; // 96

        // K xor ipad
        for (int i = 0; i < B; i++) {
            hInner[i] = secretKey[i].xorBitwise(generator.createConstantWire(0x36), 8);
        }

        // Append text to the inner hash
        for (int i = B; i < B+this.plainText.length; i++) {
            hInner[i] = this.plainText[i-B];
        }

        // h1 = H (K xor ipad, text)
        Wire[] mac = new SHA256Gadget(hInner, 8, B+this.plainText.length, false, true, "").getOutputWires();
        Wire[] macBits = new WireArray(mac).getBits(32).asArray();

        // K xor opad
        for (int i = 0; i < B; i++) {
            hOuter[i] = secretKey[i].xorBitwise(generator.createConstantWire(0x5c), 8);
        }

        // Append Bits of the previously computed SHA evaluation to the Outer Hash
        Wire[] tmp;;
        for (int i = 0; i < 32; i++) {
            if (i % 4 == 0) {
                tmp = Arrays.copyOfRange(macBits, i * 8+3*8,(i + 1) * 8+3*8);
            }
            else if (i % 4 == 1) {
                tmp = Arrays.copyOfRange(macBits, i * 8+1*8,(i + 1) * 8+1*8);
            }
            else if (i % 4 == 2) {
                tmp = Arrays.copyOfRange(macBits, i * 8-8,(i + 1) * 8-8);
            }
            else  {
                tmp = Arrays.copyOfRange(macBits, i * 8-3*8,(i + 1) * 8-3*8);
            }
            hOuter[i+B] = new WireArray(tmp).packAsBits(8);
        }

        // H (K xor opad, h1)
        Wire[] hmac = new SHA256Gadget(hOuter, 8, 96, false, true, "").getOutputWires();

        output = hmac;
    }

    private void prepare() {
		
        numBlocks = (int) this.secretKey.length % 64;

        Wire[] pad;
        Wire[] lengthBits = new Wire[64];
        pad = new Wire[numBlocks];
        
        for (int i = 0; i < pad.length; i++) {
                pad[i] = generator.getZeroWire();
            }
		
        System.arraycopy(this.secretKey, 0, lengthBits, 0, this.secretKey.length);
        System.arraycopy(pad, 0, lengthBits, 64-numBlocks, pad.length);
        this.secretKey = lengthBits;
    }

	@Override
	public Wire[] getOutputWires() {
		return output;
	}
    
}
