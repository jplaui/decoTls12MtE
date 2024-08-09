package examples.tests.kdc;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import examples.gadgets.aes_gcm.AES128WrapperGadget;
import examples.gadgets.hash.SHA256Gadget;
import examples.gadgets.kdc.KDCOPTOuterHMACGadget;
import junit.framework.TestCase;
import org.junit.Test;
import util.Util;

import java.util.Arrays;

public class KDCOPT_test extends TestCase {

    @Test
    public void testCase1(){
        CircuitGenerator generator = new CircuitGenerator("Test1_KDCOPT_OuterHMAC") {

            private Wire[] HS;
            private Wire[] innerHash;
            private Wire[] output;
            @Override
            protected void buildCircuit() {
                innerHash = createInputWireArray(32);
                HS = createProverWitnessWireArray(32);
                Wire[] output = new KDCOPTOuterHMACGadget(HS,innerHash).getOutputWires();
                makeOutputArray(output);
            }

            @Override
            public void generateSampleInput(CircuitEvaluator circuitEvaluator) {

                String HSStr = "5ac934538933f93a0bf6050f63befb268c52a7b2d3efc6cf0629b139509b11d3";
                String innerHashStr = "6738846eba35530374b8e66b708f7deb4af2dd91f1e25911b0aaad93d01bc126";
                String expectOutput = "8eb2b38d5c954863181e5be960def4b338e813fc12cd951417799f4d36e024fe";

                for (int i = 0; i < 32; i++) {
                    circuitEvaluator.setWireValue(innerHash[i], Integer.valueOf(innerHashStr.substring(i*2,i*2+2), 16));
                }
                for (int i = 0; i < 32; i++) {
                    circuitEvaluator.setWireValue(HS[i], Integer.valueOf(HSStr.substring(i*2,i*2+2), 16));
                }
            }};

        generator.generateCircuit();
        generator.evalCircuit();
        CircuitEvaluator evaluator = generator.getCircuitEvaluator();

        String outDigest = "";
        String expectedDigest = "8eb2b38d5c954863181e5be960def4b338e813fc12cd951417799f4d36e024fe";
            for (Wire w : generator.getOutWires()) {
            outDigest += Util.padZeros(evaluator.getWireValue(w).toString(16), 2);
        }
        assertEquals(outDigest, expectedDigest);
    }


    @Test
    public void testCase2(){
        CircuitGenerator generator = new CircuitGenerator("Test1_KDCOPT_2") {

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


                for (int i = 0; i < 32; i++) {
                    circuitEvaluator.setWireValue(HS[i], Integer.valueOf(HSStr.substring(i*2,i*2+2), 16));
                }
                for (int i = 0; i < 32; i++) {
                    circuitEvaluator.setWireValue(SHTSInnerHashOutput[i], Integer.valueOf(SHTSInnerHashStr.substring(i*2,i*2+2), 16));
                }
                for (int i = 0; i < 32; i++) {
                    circuitEvaluator.setWireValue(kfsInnerHashOutput[i], Integer.valueOf(kfsInnerHashStr.substring(i*2,i*2+2), 16));
                }
                for (int i = 0; i < 32; i++) {
                    circuitEvaluator.setWireValue(sfInnerHashOutput[i], Integer.valueOf(sfInnerHashStr.substring(i*2,i*2+2), 16));
                }
                for (int i = 0; i < 32; i++) {
                    circuitEvaluator.setWireValue(dHSInnerHashOutput[i], Integer.valueOf(dHSInnerHashStr.substring(i*2,i*2+2), 16));
                }
                for (int i = 0; i < 32; i++) {
                    circuitEvaluator.setWireValue(MSInnerHashOutput[i], Integer.valueOf(MSHSInnerHashStr.substring(i*2,i*2+2), 16));
                }
                for (int i = 0; i < 32; i++) {
                    circuitEvaluator.setWireValue(SATSInnerHashOutput[i], Integer.valueOf(SATSInnerHashStr.substring(i*2,i*2+2), 16));
                }
                for (int i = 0; i < 32; i++) {
                    circuitEvaluator.setWireValue(CATSInnerHashOutput[i], Integer.valueOf(CATSInnerHashStr.substring(i*2,i*2+2), 16));
                }

                for (int i = 0; i < 32; i++) {
                    circuitEvaluator.setWireValue(kSAPPKeyInnerHashOutput[i], Integer.valueOf(kSAPPKeyInnerHashStr.substring(i*2,i*2+2), 16));
                }
                for (int i = 0; i < 32; i++) {
                    circuitEvaluator.setWireValue(kSAPPIVInnerHashOutput[i], Integer.valueOf(kSAPPIVInnerHashStr.substring(i*2,i*2+2), 16));
                }

                for (int i = 0; i < 32; i++) {
                    circuitEvaluator.setWireValue(kCAPPKeyInnerHashOutput[i], Integer.valueOf(kCAPPKeyInnerHashStr.substring(i*2,i*2+2), 16));
                }
                for (int i = 0; i < 32; i++) {
                    circuitEvaluator.setWireValue(kCAPPIVInnerHashOutput[i], Integer.valueOf(kCAPPIVInnerHashStr.substring(i*2,i*2+2), 16));
                }
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
        };

        generator.generateCircuit();
        generator.evalCircuit();
        CircuitEvaluator evaluator = generator.getCircuitEvaluator();

        String outDigest = "";
        String expectedDigest = "2c6069cd44a3bb25a9b872bc";
        for (Wire w : generator.getOutWires()) {
            outDigest += Util.padZeros(evaluator.getWireValue(w).toString(16), 2);
        }
        assertEquals(outDigest, expectedDigest);
    }

}
