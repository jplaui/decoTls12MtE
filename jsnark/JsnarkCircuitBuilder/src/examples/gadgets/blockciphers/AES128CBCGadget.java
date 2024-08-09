package examples.gadgets.blockciphers;

import circuit.operations.Gadget;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import util.Util;

import java.util.Arrays;


public class AES128CBCGadget extends Gadget {
    private Wire[] ciphertext;
    private String cipherName;

    private Wire[] keyBits;
    private Wire[] plaintextBits;

    private Wire[] plaintext;
    private Wire[] ivBits;

    private Wire[] key;
    private Wire[] iv;

    private final int blocksize = 128;
    private final int keysize = 128;

    private final int bitPerWire = 8;
    @Override
    public Wire[] getOutputWires() {
        return ciphertext;
    }

    public AES128CBCGadget(Wire[] plaintext, Wire[] key,
                           Wire[] iv, int bitPerWire, boolean padding, String cipherName, String... desc) {

        super(desc);
        if (padding) {
            throw new IllegalArgumentException("padding not supported in this version!");
        }
        if (padding == false && plaintext.length % 16 != 0) {
            throw new IllegalArgumentException("plaintext bit");
        }
        if(key.length * bitPerWire != keysize || iv.length * bitPerWire != keysize){
            throw new IllegalArgumentException("Key and IV bit vectors should be of length 128");
        }
        if (this.bitPerWire != bitPerWire) {
            throw new IllegalArgumentException("bit per wire should be of length 8");
        }
        this.cipherName = cipherName;
        this.plaintext = plaintext;
        this.key = key;
        this.iv = iv;
        buildCircuit();
    }

    protected void buildCircuit() {
        preparedPlaintext(bitPerWire);
        int numBlocks = (int) Math.ceil(plaintextBits.length * 1.0 / blocksize);
        plaintextBits = new WireArray(plaintextBits).adjustLength(numBlocks * blocksize).asArray();
        Wire[] preparedKey = prepareKey();
        WireArray prevCipher = new WireArray(ivBits);

        ciphertext = new Wire[0];
        for (int i = 0; i < numBlocks; i++) {
            WireArray msgBlock = new WireArray(Arrays.copyOfRange(plaintextBits, i
                    * blocksize, (i + 1) * blocksize));
            Wire[] xored = msgBlock.xorWireArray(prevCipher).asArray();
            if (cipherName.equals("AES128CBC")) {
                Wire[] tmp = new WireArray(xored).packBitsIntoWords(8);
                Gadget gadget = new AES128CipherGadget(tmp, preparedKey);
                Wire[] outputs = gadget.getOutputWires();
                prevCipher = new WireArray(outputs).getBits(8);
            } else {
                throw new UnsupportedOperationException("Other Ciphers or modes not supported in this version!");
            }
            ciphertext = Util.concat(ciphertext,
                    prevCipher.packBitsIntoWords(8));
        }
    }

    private Wire[] prepareKey() {

        Wire[] preparedKey;
        if (cipherName.equals("AES128CBC")) {
            preparedKey = AES128CipherGadget.expandKey(key);
        } else {
            throw new UnsupportedOperationException("Other Ciphers not supported in this version!");
        }
        return preparedKey;
    }

    private void preparedPlaintext(int bitWidthPerWire) {
        plaintextBits = new WireArray(plaintext).getBits(bitWidthPerWire).asArray();
        ivBits = new WireArray(iv).getBits(bitWidthPerWire).asArray();
    }

}