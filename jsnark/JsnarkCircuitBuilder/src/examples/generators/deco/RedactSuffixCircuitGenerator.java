package examples.generators.deco;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import examples.gadgets.blockciphers.AES128CBCGadget;
import examples.gadgets.comparator.JSONFloatThresholdComparatorGadget;
import examples.gadgets.comparator.JSONKeyValuePairComparatorGadget;
import examples.gadgets.hash.SHA256DECOGadget;
import examples.gadgets.hash.SHA256Gadget;

import java.security.InvalidParameterException;
import java.util.Arrays;

public class RedactSuffixCircuitGenerator extends CircuitGenerator {

    private String secondPartInputStr;
    private String siSHA256HexStr;
    private String ivLast3rdBlockHexStr;
    private String keyMacStr;
    private String paddingStr;

    private String expectedDigestStr;

    private String keyEncStr;
    private String plaintextInlast3rdBlockStr;
    private int previousLen;

    private String keyValuePairStr;
    // the pattern at the beginning of key-value pair e.g, "price:":
    private String keyValueStartPatternInSencondInputStr;
    private String floatStr;
    // threshold in int format
    // note: solidty doesn't support float format
    private int threshold;
    private int keyValuePairWiresLen;
    // index of the beginning of key-value pair in B_{i+1}
    private int keyValuePairStartPosInJson;
    // the length of float string in JSON data; e.g, the length of float "38000.2" is 7
    private int floatStringLen;
    // the index of the dot in float string; e.g, the index of dot is 5 for "38000.2"
    private int dotPosInFloatString;
    // the maximal length of the threshold and the float number
    private int compMaxBitLen;

    private String onChainCommitStr;
    // threshold in hex string format
    private String thresholdStr;


    // second part of input corresponds to B_{i+} on deco paper
    Wire[] secondPartInputWires;
    // key mac wire is K_{mac}
    Wire[] keyMacWires;
    // key enncryption wire is AES K_{enc}
    Wire[] keyEncWires;
    // padding for AES-128-CBC in TLS
    Wire[] paddingWires;
    // s_{i}
    Wire[] siSHA256Wires;
    // initial vector for the last 3rd block
    Wire[] ivLast3rdBlockWires;
    // plaintext in the last 3rd block
    Wire[] plaintextInlast3rdBlockWires;

    // key value pair of JSON data format
    Wire[] keyValuePairWires;
    // float string extracted by key-value pair
    Wire[] floatStringWires;
    // threshold to check.
    // note: the wire array contains only one element for threshold
    Wire[] thresholdWire;

    // output: 1 for correct, 0 for wrong
    Wire compareResult;
    // expected encrypted mac (encrypted sigma)
    Wire[] expectDigestWires;
    // on-chain commit value
    Wire[] onChainCommitWires;
    // note: combing all array element can present the threshold
    // every element is 1 byte
    Wire[] thresholdInByteWires;




    public RedactSuffixCircuitGenerator(String circuitName) {
        super(circuitName);
    }

    protected void buildCircuit() {
        CircuitGenerator generator = CircuitGenerator.getActiveCircuitGenerator();
        secondPartInputWires = createProverWitnessWireArray(secondPartInputStr.length()/2);
        siSHA256Wires = createInputWireArray(siSHA256HexStr.length()/2);
        ivLast3rdBlockWires = createInputWireArray(ivLast3rdBlockHexStr.length()/2);
        keyMacWires = createInputWireArray(keyMacStr.length()/2);
        paddingWires = createInputWireArray(paddingStr.length()/2);
        expectDigestWires = createInputWireArray(expectedDigestStr.length()/2);
        keyEncWires = createProverWitnessWireArray(keyEncStr.length()/2);
        plaintextInlast3rdBlockWires = createProverWitnessWireArray(plaintextInlast3rdBlockStr.length()/2);
        keyValuePairWires = createProverWitnessWireArray(keyValuePairStr.length()/2);
        floatStringWires = createProverWitnessWireArray(floatStr.length()/2);
        thresholdWire = createProverWitnessWireArray(1);
        onChainCommitWires = createInputWireArray(onChainCommitStr.length()/8);
        thresholdInByteWires = createProverWitnessWireArray(thresholdStr.length()/2);


        Wire compKeyValueResult = new JSONKeyValuePairComparatorGadget(secondPartInputWires, secondPartInputWires.length,
        keyValuePairWires, keyValuePairStartPosInJson, keyValuePairWiresLen,
        keyValueStartPatternInSencondInputStr).getOutputWires()[0];


        Wire compThresholdResult = new JSONFloatThresholdComparatorGadget(floatStringWires, floatStringLen, dotPosInFloatString,
                thresholdWire, compMaxBitLen).getOutputWires()[0];

        compareResult = compKeyValueResult.and(compThresholdResult);

        Wire[] digest = new SHA256DECOGadget(secondPartInputWires, 8,siSHA256Wires, 8, secondPartInputWires.length,false, true,previousLen,"").getOutputWires();
        Wire[] digestBits = new WireArray(digest).getBits(32).asArray();
        Wire[] hInput = new Wire[96];
        for (int i = 0; i < 32; i++) {
            hInput[i] = keyMacWires[i].xorBitwise(generator.createConstantWire(0x5c), 8);
        }

        Arrays.fill(hInput,32,64,generator.createConstantWire(0x5c));

        Wire[] tmp;
        for (int i = 0; i < 32; i++) {
            if (i % 4 == 0) {
                tmp = Arrays.copyOfRange(digestBits, i * 8+3*8,(i + 1) * 8+3*8);
            }
            else if (i % 4 == 1) {
                tmp = Arrays.copyOfRange(digestBits, i * 8+1*8,(i + 1) * 8+1*8);
            }
            else if (i % 4 == 2) {
                tmp = Arrays.copyOfRange(digestBits, i * 8-8,(i + 1) * 8-8);
            }
            else  {
                tmp = Arrays.copyOfRange(digestBits, i * 8-3*8,(i + 1) * 8-3*8);
            }
            hInput[i+64] = new WireArray(tmp).packAsBits(8);
        }

        Wire[] mac = new SHA256Gadget(hInput, 8, 96, false, true, "").getOutputWires();
        Wire[] macBits = new WireArray(mac).getBits(32).asArray();

        Wire[] aesInput = new Wire[32];
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
            aesInput[i] = new WireArray(tmp).packAsBits(8);
        }

        final int bitPerWire = 8;
        Wire[] plaintext = new Wire[48];
        int lengthOfPlaintextInLast3rdBlock =  16 - paddingWires.length;
        int count = 0;
        if (lengthOfPlaintextInLast3rdBlock != 0) {
            for (int i = 0; i < lengthOfPlaintextInLast3rdBlock; i++ ) {
                plaintext[count++] = generator.createConstantWire(
                        Integer.valueOf(plaintextInlast3rdBlockStr.substring(i*2, (i+1)*2),16));
            }
        }

        for (int i = 0; i < 32; i++) {
            plaintext[count++] = aesInput[i];
        }

        for (int i =0; i < paddingWires.length; i++) {
            plaintext[count++] = generator.createConstantWire(Integer.valueOf(paddingStr.substring(i*2,i*2+2),16));
        }

        digest = new AES128CBCGadget(plaintext, keyEncWires, ivLast3rdBlockWires, bitPerWire, false,
                "AES128CBC",  "").getOutputWires();


        Wire[] expectedOnChainCommmit = new SHA256Gadget(thresholdInByteWires, 8, 3, false, true, "").getOutputWires();
        for (int i = 0; i < expectedOnChainCommmit.length; i++) {
            compareResult = onChainCommitWires[i].isEqualTo(expectedOnChainCommmit[i]).and(compareResult);
        }

        for (int i = 0; i < expectDigestWires.length; i++) {
            compareResult = digest[i].isEqualTo(expectDigestWires[i]).and(compareResult);
        }
        makeOutput(compareResult);
//        makeOutputArray(expectedOnChainCommmit);
    }

    @Override
    public void generateSampleInput(CircuitEvaluator e) {

        for (int i = 0; i < secondPartInputStr.length()/2; i++) {
            e.setWireValue(secondPartInputWires[i], Integer.valueOf(secondPartInputStr.substring(i*2,i*2+2),16));
        }
        for (int i = 0; i < siSHA256HexStr.length()/2; i++ ) {
            e.setWireValue(siSHA256Wires[i], Integer.valueOf(siSHA256HexStr.substring(i*2,i*2+2), 16));
        }
        for (int i = 0; i < keyMacStr.length()/2; i++) {
            e.setWireValue(keyMacWires[i], Integer.valueOf(keyMacStr.substring(i*2, i*2+2),16));
        }
        for (int i = 0; i < paddingStr.length()/2; i++) {
            e.setWireValue(paddingWires[i], Integer.valueOf(paddingStr.substring(i*2, i*2+2),16));
        }
        for (int i = 0; i < keyEncStr.length()/2; i++) {
            e.setWireValue(keyEncWires[i], Integer.valueOf(keyEncStr.substring(i*2, i*2+2),16));
        }
        for (int i = 0; i < ivLast3rdBlockHexStr.length()/2; i++ ) {
            e.setWireValue(ivLast3rdBlockWires[i], Integer.valueOf(ivLast3rdBlockHexStr.substring(i*2,i*2+2), 16));
        }

        if (plaintextInlast3rdBlockStr.length() != 0) {
            for (int i = 0; i < plaintextInlast3rdBlockStr.length()/2; i++) {
                e.setWireValue(plaintextInlast3rdBlockWires[i], Integer.valueOf(plaintextInlast3rdBlockStr.substring(i*2, i*2+2),16));
            }
        }

        for (int i = 0; i < keyValuePairStr.length()/2; i++ ){
            e.setWireValue(keyValuePairWires[i],Integer.valueOf(keyValuePairStr.substring(i*2, i*2+2),16));
        }

        for (int i = 0; i < floatStr.length()/2; i++) {
            e.setWireValue(floatStringWires[i],Integer.valueOf(
                    floatStr.substring(i*2, i*2+2),16));
        }

        for (int i =0; i < expectedDigestStr.length()/2; i++) {
            e.setWireValue(expectDigestWires[i],Integer.valueOf(expectedDigestStr.substring(i*2, i*2+2),16));
        }

        for (int i = 0; i < thresholdStr.length()/2; i++) {
            e.setWireValue(thresholdInByteWires[i], Integer.valueOf(thresholdStr.substring(i*2, i*2+2),16));
        }

        for (int i = 0; i < onChainCommitStr.length()/8; i++) {
            e.setWireValue(onChainCommitWires[i], Long.parseUnsignedLong(onChainCommitStr.substring(i*8, i*8+8),16));
        }

        e.setWireValue(thresholdWire[0], threshold);
    }

    public static void main(String[] args) throws Exception {
        RedactSuffixCircuitGenerator generator = new RedactSuffixCircuitGenerator("redact_suffix_circuit");
        if (args.length != 17) {
            System.out.println("invalid number of args: "+args.length+" args are given, expected 17 args");
            throw new InvalidParameterException("invalid number of args");
        }
        generator.secondPartInputStr = args[0];
        generator.siSHA256HexStr = args[1];
        generator.ivLast3rdBlockHexStr = args[2];
        generator.keyMacStr = args[3];
        generator.paddingStr = args[4];
        generator.keyEncStr = args[5];
        generator.plaintextInlast3rdBlockStr = args[6];
        generator.previousLen = Integer.parseInt(args[7]);
        generator.keyValuePairStr = args[8];
        generator.keyValueStartPatternInSencondInputStr = args[9];
        generator.floatStr = args[10];
        generator.expectedDigestStr = args[11];
        generator.threshold = Integer.parseInt(args[12]);
        generator.keyValuePairStartPosInJson = Integer.parseInt(args[13]);
        generator.dotPosInFloatString = Integer.parseInt(args[14]);
        generator.compMaxBitLen = Integer.parseInt(args[15]);
        generator.onChainCommitStr = args[16];

//    generator.secondPartInputStr = "696e636f6d65223a22312c3330302c353631204575726f227d2c227072696365223a2233383030302e32222c2274696d65223a2231323a30303a3030222c22766f6c756d65223a22333231363534227d";
//    generator.siSHA256HexStr = "862b84f66bee3a313e08e8000d3303cd22e10f080de65992da4f742e6d76b472";
//    generator.ivLast3rdBlockHexStr = "9919da2f3a559a257bc7ab461b86898b";
//    generator.keyMacStr = "8962bb327b637ef54df004937cb3932a13f4e35ebc734dc6f3d732b1f6b1c778";
//    generator.paddingStr = "0c0c0c0c0c0c0c0c0c0c0c0c0c";
//
//
//    generator.keyEncStr = "935db6a9dd7b5ce23ac9acbc519a1992";
//    generator.plaintextInlast3rdBlockStr = "34227d";
//    generator.previousLen = 192;
//
//    generator.keyValuePairStr = "227072696365223a2233383030302e32222c";
//    generator.keyValueStartPatternInSencondInputStr = "227072696365223a22";
//    generator.floatStr = "33383030302e32";
//    generator.expectedDigestStr = "5620b4b5c7437fe1425f717f409045b27fb100ac652848bcdc05a0c7fadd0be4ca106e7d244d1602294b33fc43ad9db9";
//
//    generator.threshold = 380001;
//    generator.keyValuePairStartPosInJson = 26;
//    generator.dotPosInFloatString = 5;
//    generator.compMaxBitLen = 20;
//    generator.onChainCommitStr = "aa8586ce4ae9d6799733c8f849397c39fdc9f9c2fd3ead72b2c6011b80795967";
//    generator.thresholdStr = Integer.toHexString(generator.threshold);
    generator.thresholdStr = "05cc61";
        // following parameters are only derived by inputs
    generator.keyValuePairWiresLen = generator.keyValuePairStr.length()/2;
    generator.floatStringLen = generator.floatStr.length()/2;


    generator.generateCircuit();
    generator.evalCircuit();
    generator.prepFiles();
//    generator.runLibsnark();

    }

}
