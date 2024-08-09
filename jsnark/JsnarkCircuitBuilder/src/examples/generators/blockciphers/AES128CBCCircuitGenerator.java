package examples.generators.blockciphers;

import circuit.config.Config;
import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import examples.gadgets.blockciphers.AES128CBCGadget;
import examples.gadgets.blockciphers.AES128CipherGadget;


// A sample usage of the AES128 CBC gadget
public class AES128CBCCircuitGenerator extends CircuitGenerator {

    private Wire[] plaintext;
    private Wire[] key;
    private Wire[] iv;
    private Wire[] ciphertext;

    private AES128CipherGadget gadget;

    public AES128CBCCircuitGenerator(String circuitName) {
        super(circuitName);
    }

    @Override
    protected void buildCircuit() {
        int bitPerWire = 8;
        plaintext = createProverWitnessWireArray(32);
//        plaintext = createInputWireArray(32);
        key = createInputWireArray(16);
        iv = createInputWireArray(16);
        ciphertext = new AES128CBCGadget(plaintext, key, iv, bitPerWire, false,
                "AES128CBC",  "").getOutputWires();
        makeOutputArray(ciphertext);
        for (Wire c : ciphertext) {
            makeOutput(c);
        }

    }

    @Override
    public void generateSampleInput(CircuitEvaluator circuitEvaluator) {

        String ivHexStr = "f5d3d58503b9699de785895a96fdbaaf";
        String keyHexStr = "2b7e151628aed2a6abf7158809cf4f3c";
        String msgHexStr = "94a5601fbb598c548d7b5f0c2cc6c5589dfac01344f613a9bde729a8c6f6ac19";


        for (int i = 0; i < plaintext.length; i++) {
            circuitEvaluator.setWireValue(plaintext[i], Integer.valueOf(msgHexStr.substring(i*2,i*2+2), 16));
        }
        for (int i = 0; i < key.length; i++) {
            circuitEvaluator.setWireValue(key[i], Integer.valueOf(keyHexStr.substring(i*2,i*2+2), 16));
        }

        for (int i = 0; i < iv.length; i++ ) {
            circuitEvaluator.setWireValue(iv[i], Integer.valueOf(ivHexStr.substring(i*2,i*2+2), 16));
        }
    }

    public static void main(String[] args) throws Exception {

        Config.hexOutputEnabled = true;
        AES128CBCCircuitGenerator generator = new AES128CBCCircuitGenerator(
                "AES128CBC_Circuit");
        generator.generateCircuit();
        generator.evalCircuit();
        generator.prepFiles();
        generator.runLibsnark();

    }
}
