package examples.generators.hash;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import examples.gadgets.hash.SHA256DECOGadget;

public class SHA256DECOGenerator extends CircuitGenerator {

    private Wire[] inputWires;

    private Wire[] ivWires;
    private SHA256DECOGadget sha256DECOGadget;

    public SHA256DECOGenerator(String circuitName) {
        super(circuitName);
    }

    @Override
    protected void buildCircuit() {

        // assuming the circuit input will be 64 bytes
        inputWires = createInputWireArray(64);
        ivWires = createInputWireArray(32);
        // this gadget is not applying any padding.
        sha256DECOGadget = new SHA256DECOGadget(inputWires, 8, ivWires,
                8, 64,false,false,0);
        Wire[] digest = sha256DECOGadget.getOutputWires();
        makeOutputArray(digest, "digest");

    }

    @Override
    public void generateSampleInput(CircuitEvaluator e) {
        String inputStr = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        String ivHexStr = "6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19";

        for (int i = 0; i < inputWires.length; i++) {
            e.setWireValue(inputWires[i], Integer.valueOf(inputStr.substring(i * 2, i * 2 + 2), 16));
        }
        for (int i = 0; i < ivWires.length; i++) {
            e.setWireValue(ivWires[i], Integer.valueOf(ivHexStr.substring(i * 2, i * 2 + 2), 16));
        }
    }

    public static void main(String[] args) throws Exception {
        SHA256DECOGenerator generator = new SHA256DECOGenerator("SHA256_DECO_Generator");
        generator.generateCircuit();
        generator.evalCircuit();
        generator.prepFiles();
        generator.runLibsnark();
    }

}
