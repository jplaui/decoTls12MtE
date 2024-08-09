package examples.tests.comparator;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import examples.gadgets.comparator.JSONFloatThresholdComparatorGadget;
import junit.framework.TestCase;
import org.junit.Test;

import java.math.BigInteger;

public class JSONFloatThresholdComparison_Test extends TestCase {

    @Test
    public void testCase1() {
        CircuitGenerator generator = new CircuitGenerator("JSONFloatThresholdComparison_Test1") {

            private Wire[] floatStringWires;
            private Wire[] thresholdWire;

            // float string: "12.2313", float string length: 7
            // threshold=0x1D9E0=121312, both float/threshold requires 17 bits to store
            private int floatStringLen = 7;
            private int compareMaxBitLength = 17;
            private int dotPosition = 2;

            @Override
            protected void buildCircuit() {
                floatStringWires = createProverWitnessWireArray(floatStringLen);
                thresholdWire = createProverWitnessWireArray(1);
                Wire[] output = new JSONFloatThresholdComparatorGadget(floatStringWires, floatStringLen, dotPosition, thresholdWire, compareMaxBitLength).getOutputWires();
                makeOutput(output[0]);
            }

            @Override
            public void generateSampleInput(CircuitEvaluator evaluator) {

                String floatStr = "12.2313";
                BigInteger threshold = BigInteger.valueOf(121312);
                for (int i = 0; i < floatStringWires.length; i++) {
                        evaluator.setWireValue(floatStringWires[i], BigInteger.valueOf(floatStr.charAt(i)));
                }
                evaluator.setWireValue(thresholdWire[0], threshold);
            }

        };
        generator.generateCircuit();
        generator.evalCircuit();
        CircuitEvaluator evaluator = generator.getCircuitEvaluator();
        Wire out = generator.getOutWires().get(0);
        // expected output should be true
        assertEquals(evaluator.getWireValue(out), BigInteger.ONE);
    }


    @Test
    public void testCase2() {
        CircuitGenerator generator = new CircuitGenerator("JSONFloatThresholdComparison_Test1") {

            private Wire[] floatStringWires;
            private Wire[] thresholdWire;

            private Wire compareResult;

            // float string: "342.23", float string length: 6
            // threshold=34224, compareMaxBitLength = 16
            private int floatStringLen = 6;
            private int compareMaxBitLength = 16;
            private int dotPosition = 3;

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
                BigInteger threshold = BigInteger.valueOf(34224);
                for (int i = 0; i < floatStringWires.length; i++) {
                    evaluator.setWireValue(floatStringWires[i], BigInteger.valueOf(floatStr.charAt(i)));
                }
                evaluator.setWireValue(thresholdWire[0], threshold);
            }

        };
        generator.generateCircuit();
        generator.evalCircuit();
        CircuitEvaluator evaluator = generator.getCircuitEvaluator();
        Wire out = generator.getOutWires().get(0);
        // expect output should be false
        assertEquals(evaluator.getWireValue(out), BigInteger.ZERO);
    }
}
