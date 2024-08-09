package examples.generators.kdc;

import circuit.config.Config;
import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import examples.gadgets.kdc.KDCOPTOuterHMACGadget;

import java.util.Arrays;


public class KDCOPTGenerator extends CircuitGenerator {
    private Wire[] HS;
    private Wire[] SHTSInnerHashOutput;
    private Wire[] output;
//    private Wire[] SHTS;
    private Wire[] kfsInnerHashOutput;
    private Wire[] sfInnerHashOutput;
    private Wire[] dHSInnerHashOutput;
    private Wire[] MSInnerHashOutput;
    private Wire[] SATSInnerHashOutput;
    private Wire[] CATSInnerHashOutput;
    private Wire[] kSAPPKeyInnerHashOutput;
    private Wire[] kSAPPIVInnerHashOutput;
    private Wire[] kCAPPKeyInnerHashOutput;
    private Wire[] kCAPPIVInnerHashOutput;

    public KDCOPTGenerator(String circuitName) {
        super(circuitName);
    }

    @Override
    protected void buildCircuit() {
        HS = createProverWitnessWireArray(32);
        SHTSInnerHashOutput = createInputWireArray(32);
        kfsInnerHashOutput = createInputWireArray(32);
        sfInnerHashOutput = createInputWireArray(32);
        dHSInnerHashOutput = createInputWireArray(32);
        MSInnerHashOutput = createInputWireArray(32);
        SATSInnerHashOutput = createInputWireArray(32);
        CATSInnerHashOutput = createInputWireArray(32);
        kSAPPKeyInnerHashOutput = createInputWireArray(32);
        kSAPPIVInnerHashOutput = createInputWireArray(32);
        kCAPPKeyInnerHashOutput = createInputWireArray(32);
        kCAPPIVInnerHashOutput = createInputWireArray(32);

        Wire[] SHTS = new KDCOPTOuterHMACGadget(HS,SHTSInnerHashOutput).getOutputWires();
        Wire[] SHTSByteFormat = formatOutput(SHTS);
        Wire[] kfs = new KDCOPTOuterHMACGadget(SHTSByteFormat,kfsInnerHashOutput).getOutputWires();
        Wire[] kfsByteFormat = formatOutput(kfs);
        Wire[] SF = new KDCOPTOuterHMACGadget(kfsByteFormat, sfInnerHashOutput).getOutputWires();
        Wire[] SFByteFormat = formatOutput(SF);
        Wire[] dHS = new KDCOPTOuterHMACGadget(HS, dHSInnerHashOutput).getOutputWires();
        Wire[] dHSByteFormat = formatOutput(dHS);
        Wire[]  MS = new KDCOPTOuterHMACGadget(dHSByteFormat, MSInnerHashOutput).getOutputWires();
        Wire[] MSByteFormat = formatOutput(MS);
        Wire[]  SATS = new KDCOPTOuterHMACGadget(MSByteFormat, SATSInnerHashOutput).getOutputWires();
        Wire[] SATSByteFormat = formatOutput(SATS);
        Wire[]  kSAPPKey = new KDCOPTOuterHMACGadget(SATSByteFormat, kSAPPKeyInnerHashOutput).getOutputWires();
        Wire[]  kSAPPIV = new KDCOPTOuterHMACGadget(SATSByteFormat, kSAPPIVInnerHashOutput).getOutputWires();

        Wire[]  CATS = new KDCOPTOuterHMACGadget(MSByteFormat, CATSInnerHashOutput).getOutputWires();
        Wire[] CATSByteFormat = formatOutput(CATS);
        Wire[]  kCAPPKey = new KDCOPTOuterHMACGadget(CATSByteFormat, kCAPPKeyInnerHashOutput).getOutputWires();
        Wire[]  kCAPPIV = new KDCOPTOuterHMACGadget(CATSByteFormat, kCAPPIVInnerHashOutput).getOutputWires();

        Wire[] kSAPPKeyByteFormat = formatOutput(kSAPPKey);
        kSAPPKeyByteFormat = truncate(kSAPPKeyByteFormat, 16);
        Wire[] kSAPPIVByteFormat = formatOutput(kSAPPIV);
        kSAPPIVByteFormat = truncate(kSAPPIVByteFormat, 12);

        Wire[] kCAPPKeyByteFormat = formatOutput(kCAPPKey);
        kCAPPKeyByteFormat = truncate(kCAPPKeyByteFormat, 16);
        Wire[] kCAPPIVByteFormat = formatOutput(kCAPPIV);
        kCAPPIVByteFormat = truncate(kCAPPIVByteFormat, 12);
        output = kCAPPIVByteFormat;
        makeOutputArray(output, "digest");

    }

    @Override
    public void generateSampleInput(CircuitEvaluator circuitEvaluator) {

        String HSStr = "45073a01656ca5d43508352f349088e8ff25ff1a1ec8cc3f30cef832b2dd9add";
        String SHTSInnerHashStr = "3a6857cf5e19272770bad5748b7ec784e835bfae17d49c599fe35f041fe31faa";
        String kfsInnerHashStr = "afa7a9a1a5c5641e038a15cbb549ad15ddd944b565e19ab70181764aecaa1943";
        String sfInnerHashStr = "435e4481302875e9be0aeff45663fee79c8dc7f3ace7bbddc63c84d9ea01ebb3";
        String dHSInnerHashStr = "a1357b0f1a2f28bf8015192584d9080bbb85a38f4b39080215400eebc18f7f26";
        String MSHSInnerHashStr = "58aa7a0017bec7140e087b191a1f04904461fba1d54b3020f656c08528446efb";
        String SATSInnerHashStr = "bb2d4af0845e2d9489994cde6fb7c5136dbb99b90f92d1e53ba3107a2e3c7441";
        String CATSInnerHashStr = "3a36015550a9b290602c7ba0b403cc28a98f86ef98df5a25075be2b42ed1484b";
        String kSAPPKeyInnerHashStr = "81430ab6b79ca1467a08636ced56bbec47b02b2167eae925321985475b94521b";
        String kSAPPIVInnerHashStr = "c0f1212dff7aefbeb22dad57b288d90b675d259ddb42926fa2079f027ea8ba15";
        String kCAPPKeyInnerHashStr = "51cfb34a313c8bef045f8638fc7e8469fd4bbb3a56e101d0f2d9000e9a3c0f81";
        String kCAPPIVInnerHashStr = "a23281ccbc0ec51126df58dade03e8d9f8be3c072f3a80926fe0b95e2bd1a19c";
        String expectOutput = "2c6069cd44a3bb25a9b872bc";


        setWires(HS, HSStr, circuitEvaluator);
        setWires(SHTSInnerHashOutput, SHTSInnerHashStr, circuitEvaluator);
        setWires(kfsInnerHashOutput, kfsInnerHashStr, circuitEvaluator);
        setWires(sfInnerHashOutput, sfInnerHashStr, circuitEvaluator);
        setWires(dHSInnerHashOutput, dHSInnerHashStr, circuitEvaluator);
        setWires(MSInnerHashOutput, MSHSInnerHashStr, circuitEvaluator);
        setWires(SATSInnerHashOutput, SATSInnerHashStr, circuitEvaluator);
        setWires(CATSInnerHashOutput, CATSInnerHashStr, circuitEvaluator);
        setWires(kSAPPKeyInnerHashOutput, kSAPPKeyInnerHashStr, circuitEvaluator);
        setWires(kSAPPIVInnerHashOutput, kSAPPIVInnerHashStr, circuitEvaluator);
        setWires(kCAPPKeyInnerHashOutput, kCAPPKeyInnerHashStr, circuitEvaluator);
        setWires(kCAPPIVInnerHashOutput, kCAPPIVInnerHashStr, circuitEvaluator);
    }

    private Wire[] formatOutput(Wire[] Bits32Wire) {
        Wire[] Bits8Wire = new Wire[Bits32Wire.length*4];
        Wire[] WireBits = new WireArray(Bits32Wire).getBits(32).asArray();
        Wire[] tmp;
        int idx = 0;
        for (int i = 0; i < 32; i++) {
            if (i % 4 == 0) {
                tmp = Arrays.copyOfRange(WireBits, i * 8+3*8,(i + 1) * 8+3*8);
            }
            else if (i % 4 == 1) {
                tmp = Arrays.copyOfRange(WireBits, i * 8+1*8,(i + 1) * 8+1*8);
            }
            else if (i % 4 == 2) {
                tmp = Arrays.copyOfRange(WireBits, i * 8-8,(i + 1) * 8-8);
            }
            else  {
                tmp = Arrays.copyOfRange(WireBits, i * 8-3*8,(i + 1) * 8-3*8);
            }
            Bits8Wire[idx++] = new WireArray(tmp).packAsBits(8);
        }
        return Bits8Wire;

    }

    private Wire[] truncate(Wire[] wires, int length) {
        Wire[] truncatedWires = new Wire[length];
        System.arraycopy(wires, 0, truncatedWires, 0, length);
        return truncatedWires;
    }

    private void setWires(Wire[] wires, String inputStr, CircuitEvaluator circuitEvaluator) {
        for (int i = 0; i < inputStr.length()/2; i++) {
            circuitEvaluator.setWireValue(wires[i], Integer.valueOf(inputStr.substring(i*2,i*2+2), 16));
        }
    }



    public static void main(String[] args) throws Exception {
        Config.hexOutputEnabled = true;
        KDCOPTGenerator generator = new KDCOPTGenerator(
                "KDCOPT_Circuit");
        generator.generateCircuit();
        generator.evalCircuit();
        generator.prepFiles();
        generator.runLibsnark();
    }


}
