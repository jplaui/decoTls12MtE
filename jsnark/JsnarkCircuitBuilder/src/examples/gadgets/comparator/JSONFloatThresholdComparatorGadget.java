package examples.gadgets.comparator;

import circuit.operations.Gadget;
import circuit.structure.Wire;

import java.math.BigInteger;


public class JSONFloatThresholdComparatorGadget extends Gadget {

    private Wire[] floatStringWires;
    private Wire[] thresholdWire;
    private Wire compareResult;

    private int floatStringLen;
    private int compareMaxBitLength;
    private int dotPosition;

    public JSONFloatThresholdComparatorGadget(Wire[] floatStringWires, int floatStringLen, int dotPosition,
                                              Wire[] thresholdWire, int compareMaxBitLength, String... desc) {

        super(desc);
        this.floatStringWires = floatStringWires;
        this.thresholdWire = thresholdWire;
        this.floatStringLen = floatStringLen;
        this.dotPosition = dotPosition;
        this.compareMaxBitLength = compareMaxBitLength;
        buildCircuit();

    }

    protected void buildCircuit() {
        Wire scaledFloat = generator.getZeroWire();

        for (int i = 0; i < floatStringLen; i++) {
            if (i < dotPosition) {
                // sub is for conversion of ascii char "0" to number 0
                scaledFloat = scaledFloat.add(floatStringWires[i].sub(48).mul(BigInteger.valueOf(10).pow(floatStringLen - 1 - 1 - i)));
            } else if (i > dotPosition) {
                scaledFloat = scaledFloat.add(floatStringWires[i].sub(48).mul(BigInteger.valueOf(10).pow(floatStringLen - 1 - i)));
            }
        }
        // thresholdWire[0] contains the total threshold that need to check
        compareResult = scaledFloat.isGreaterThanOrEqual(thresholdWire[0], compareMaxBitLength);
        compareResult = floatStringWires[dotPosition].isEqualTo(generator.getOneWire().mul('.')).and(compareResult);

    }


    /**
     * outputs: boolean presented in 8-bit
     */
    @Override
    public Wire[] getOutputWires() {
        return new Wire[]{compareResult};
    }
}
