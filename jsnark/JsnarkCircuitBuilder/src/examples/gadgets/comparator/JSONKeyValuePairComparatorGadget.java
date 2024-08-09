package examples.gadgets.comparator;

import circuit.operations.Gadget;
import circuit.structure.Wire;

import java.math.BigInteger;


public class JSONKeyValuePairComparatorGadget extends Gadget {
    private Wire[] keyValuePairWires;
    private Wire[] jsonPlaintextWires;

    private  Wire compareResult;
    private int jsonPlaintextLen;

    // start index of key-value pair in the json format data
    private int keyValuePairStartPosInJson;

    // key-value pair string length
    private int keyValuePairWiresLen;

    // key-value first pattern in the beginning
    // e.g. "227072696365223a22" pattern stands for "price":"
    private String keyValueStartPatternStr ;



    public JSONKeyValuePairComparatorGadget(Wire[] jsonPlaintextWires, int jsonPlaintextLen,
                                            Wire[] keyValuePairWires, int keyValuePairStartPosInJson, int keyValuePairWiresLen,
                                            String keyValueStartPatternStr, String... desc) {

        super(desc);
        this.jsonPlaintextWires = jsonPlaintextWires;
        this.jsonPlaintextLen = jsonPlaintextLen;
        this.keyValuePairWires = keyValuePairWires;
        this.keyValuePairStartPosInJson = keyValuePairStartPosInJson;
        this.keyValueStartPatternStr = keyValueStartPatternStr;
        this.keyValuePairWiresLen = keyValuePairWiresLen;
        buildCircuit();
    }

    protected void buildCircuit() {
        compareResult =  generator.getOneWire();
        // for example "227072696365223a22" stands for \"price\": , keyValueFirstPatternLen should be half of the pattern string length
        int keyValueStartPatternLen = keyValueStartPatternStr.length()/2;

        Wire[] firstPattern = new Wire[keyValueStartPatternLen];

        for (int i = 0; i < keyValueStartPatternLen; i++) {
            firstPattern[i] = generator.createConstantWire(Integer.valueOf(keyValueStartPatternStr.substring(i*2,i*2+2),16));
        }

        int count = 0;
        for (int i = 0; i < keyValuePairWiresLen; i++) {
            if (count < keyValueStartPatternLen) {
                compareResult = keyValuePairWires[count].isEqualTo(firstPattern[count]).and(compareResult);
            } else if (count == jsonPlaintextLen - 1) {
                compareResult = keyValuePairWires[count].isEqualTo(
                        generator.createConstantWire(BigInteger.valueOf('"'))).and(compareResult);
            }
            compareResult = jsonPlaintextWires[i+keyValuePairStartPosInJson].isEqualTo(keyValuePairWires[count++]).and(compareResult);
        }
    }


    /**
     * outputs: boolean presented in 8-bit
     */
    @Override
    public Wire[] getOutputWires() {
        return new Wire[]{compareResult};
    }
}
