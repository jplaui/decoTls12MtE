package examples.generators.comparator;


import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;

import examples.gadgets.comparator.JSONFloatThresholdComparatorGadget;

import java.math.BigInteger;

public class JSONFloatThresholdComparatorGenerator extends CircuitGenerator {

    private Wire[] floatStringWires;
    private Wire[] thresholdWire;

    // float string: "342.23", float string length: 6
    // threshold=34222, thresholdBitLength= 16

    private int floatStringLen = 6;
    private int compareMaxBitLength = 16;
    private int dotPosition = 3;
    public JSONFloatThresholdComparatorGenerator(String circuitName) {
        super(circuitName);
    }

    @Override
    protected void buildCircuit() {
        floatStringWires = createProverWitnessWireArray(floatStringLen);
        thresholdWire = createProverWitnessWireArray(1);
        Wire[] output = new JSONFloatThresholdComparatorGadget(floatStringWires, floatStringLen, dotPosition, thresholdWire, compareMaxBitLength).getOutputWires();
        makeOutput(output[0]);
    }

    @Override
    public void generateSampleInput(CircuitEvaluator evaluator) {

        String floatStr = "342.23";
        BigInteger threshold = BigInteger.valueOf(34222);
        for (int i = 0; i < floatStringWires.length; i++) {
            evaluator.setWireValue(floatStringWires[i], BigInteger.valueOf(floatStr.charAt(i)));
        }
        evaluator.setWireValue(thresholdWire[0], threshold);
    }

    public static void main(String[] args) throws Exception {

        int floatStringLen = 6;
        int compareMaxBitLength = 16;
        int dotPosition = 3;

        examples.generators.comparator.JSONFloatThresholdComparatorGenerator generator
                = new examples.generators.comparator.JSONFloatThresholdComparatorGenerator(
                "JSONFloatThresholdComparator_Circuit");
        generator.floatStringLen = floatStringLen;
        generator.compareMaxBitLength = compareMaxBitLength;
        generator.dotPosition = dotPosition;
        generator.generateCircuit();
        generator.evalCircuit();
        generator.prepFiles();
        generator.runLibsnark();

    }
}