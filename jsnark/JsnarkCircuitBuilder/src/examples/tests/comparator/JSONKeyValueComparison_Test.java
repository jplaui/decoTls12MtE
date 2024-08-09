package examples.tests.comparator;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import examples.gadgets.comparator.JSONKeyValuePairComparatorGadget;
import junit.framework.TestCase;
import org.junit.Test;

import java.math.BigInteger;


public class JSONKeyValueComparison_Test extends TestCase {

    @Test
    public void testCase1() {
        CircuitGenerator generator = new CircuitGenerator("JSONKeyValueComparison_Test1") {

            private Wire[] keyValuePairWires;
            private Wire[] jsonPlaintextWires;

            private int jsonPlaintextLen = 62;
            private int keyValuePairStartPosInJson = 4;
            private int keyValuePairWiresLen = 18;
            private String keyValueStartPatternStr = convertASCIIStringToHexString("\"distance\":\"");

            @Override
            protected void buildCircuit() {
                keyValuePairWires = createProverWitnessWireArray(keyValuePairWiresLen);
                jsonPlaintextWires = createProverWitnessWireArray(jsonPlaintextLen);

                Wire[] compareResult = new JSONKeyValuePairComparatorGadget(jsonPlaintextWires, jsonPlaintextLen, keyValuePairWires,
                        keyValuePairStartPosInJson, keyValuePairWiresLen, keyValueStartPatternStr).getOutputWires();
                makeOutput(compareResult[0]);
            }

            @Override
            public void generateSampleInput(CircuitEvaluator evaluator) {

                String keyValuePairStr = "\"distance\":\"12.13\"";
                String jsonPlaintextStr = "    \"distance\":\"12.13\", \"fwef............++++++++********////////........\"";

                String keyValuePairHexString = convertASCIIStringToHexString(keyValuePairStr);
                String jsonPlaintextHexStr = convertASCIIStringToHexString(jsonPlaintextStr);

                for (int i = 0; i < keyValuePairWires.length; i++) {
                    evaluator.setWireValue(keyValuePairWires[i], Integer.valueOf(keyValuePairHexString.substring(i*2, i*2+2),16));
                }
                for (int i = 0; i < jsonPlaintextWires.length; i++) {
                    evaluator.setWireValue(jsonPlaintextWires[i], Integer.valueOf(jsonPlaintextHexStr.substring(i*2,i*2+2), 16));
                }
            }

        };
        generator.generateCircuit();
        generator.evalCircuit();
        CircuitEvaluator evaluator = generator.getCircuitEvaluator();
        Wire out = generator.getOutWires().get(0);
        assertEquals(evaluator.getWireValue(out), BigInteger.ONE);
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
}
