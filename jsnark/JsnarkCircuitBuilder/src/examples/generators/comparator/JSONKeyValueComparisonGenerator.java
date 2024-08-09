package examples.generators.comparator;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import examples.gadgets.comparator.JSONFloatThresholdComparatorGadget;

import java.math.BigInteger;

public class JSONKeyValueComparisonGenerator extends CircuitGenerator {

    private Wire[] keyValuePairWires;
    private Wire[] jsonPlaintextWires;

    private int jsonPlaintextLen;
    private int keyValuePairStartPosInJson;
    private int keyValuePairWiresLen;
    private String keyValueStartPatternStr;

    public JSONKeyValueComparisonGenerator(String circuitName) {
        super(circuitName);
    }

    @Override
    protected void buildCircuit() {
        keyValuePairWires = createProverWitnessWireArray(keyValuePairWiresLen);
        jsonPlaintextWires = createProverWitnessWireArray(jsonPlaintextLen);

        Wire[] compareResult = new examples.gadgets.comparator.JSONKeyValuePairComparatorGadget(jsonPlaintextWires, jsonPlaintextLen, keyValuePairWires,
                keyValuePairStartPosInJson, keyValuePairWiresLen, keyValueStartPatternStr).getOutputWires();
        makeOutput(compareResult[0]);

    }

    @Override
    public void generateSampleInput(CircuitEvaluator evaluator) {

        String keyValuePairStr = "227072696365223a2233383030302e32222c22";
        String jsonPlaintextStr ="227072696365223a2233383030302e32222c000001111133333322";
        for (int i = 0; i < keyValuePairWires.length; i++) {
            evaluator.setWireValue(keyValuePairWires[i], Integer.valueOf(keyValuePairStr.substring(i*2,i*2+2),16));
        }
        for (int i = 0; i < jsonPlaintextWires.length; i++) {
            evaluator.setWireValue(jsonPlaintextWires[i], Integer.valueOf(jsonPlaintextStr.substring(i*2,i*2+2),16));
        }
    }

    public static void main(String[] args) throws Exception {

        int jsonPlaintextLen = 27;
        int keyValuePairStartPosInJson = 4;
        int keyValuePairWiresLen = 18;
        String keyValueStartPatternStr ="227072696365223a22";

        examples.generators.comparator.JSONKeyValueComparisonGenerator generator
                = new examples.generators.comparator.JSONKeyValueComparisonGenerator(
                "JSONKeyValueComparison_Circuit");
        generator.jsonPlaintextLen = jsonPlaintextLen;
        generator.keyValuePairStartPosInJson = keyValuePairStartPosInJson;
        generator.keyValuePairWiresLen = keyValuePairWiresLen;
        generator.keyValueStartPatternStr = keyValueStartPatternStr;
        generator.generateCircuit();
        generator.evalCircuit();
        generator.prepFiles();
        generator.runLibsnark();

    }
}
