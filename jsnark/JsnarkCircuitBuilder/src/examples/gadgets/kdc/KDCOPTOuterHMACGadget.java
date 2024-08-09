package examples.gadgets.kdc;

import circuit.operations.Gadget;
import circuit.structure.Wire;
import examples.gadgets.hash.SHA256Gadget;

import java.util.Arrays;

public class KDCOPTOuterHMACGadget extends Gadget {
    private Wire[] output;

    private Wire[] xorWirePad(Wire[] wire, int pad) {
        for (int i = 0; i < 32; i++) {
            wire[i] = wire[i].xorBitwise(generator.createConstantWire(pad), 8);
        }
        Arrays.fill(wire, 32,  64, generator.createConstantWire(pad));
        return wire;
    }

    public KDCOPTOuterHMACGadget(Wire[] HS, Wire[] innerHash, String... desc) {
        super(desc);
        buildCircuit(HS, innerHash);
    }

    protected void buildCircuit(Wire[] HS, Wire[] innerHash) {
        Wire [] opad = new Wire[64];
        System.arraycopy(HS, 0, opad, 0, HS.length);
        opad = xorWirePad(opad,0x5c);
        Wire[] outerHashInput = new Wire[96];
        System.arraycopy(opad, 0, outerHashInput, 0, opad.length);
        System.arraycopy(innerHash,0, outerHashInput, 64,32 );
        output = new SHA256Gadget(outerHashInput, 8, outerHashInput.length, false,
                true, "HMAC_outerHash").getOutputWires();
    }

    /**
     * outputs: boolean presented in 8-bit
     */
    @Override
    public Wire[] getOutputWires() {
        return output;
    }
}
