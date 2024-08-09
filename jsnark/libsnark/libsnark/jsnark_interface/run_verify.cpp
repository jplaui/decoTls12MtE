#include <string>
#include <iostream>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include "CircuitReader.hpp"
#include "libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp"


int main(int argc, char* argv[]) {
    cout << "verify..." <<endl;
    libff::start_profiling();
    gadgetlib2::initPublicParamsFromDefaultPp();
    gadgetlib2::GadgetLibAdapter::resetVariableIndex();
    ProtoboardPtr pb = gadgetlib2::Protoboard::create(gadgetlib2::R1P);
    if (argc != 7) {
        cout << "invalid number of args" <<endl;
        throw std::invalid_argument("The number of args should be 5");
    }

    string si = argv[1];
    string ivAES = argv[2];
    string keyMAC = argv[3];
    string padding = argv[4];
    string cipher_sigma_blocks = argv[5];
    string on_chain_commit = argv[6];
    string statement_in_8bits = si + ivAES + keyMAC + padding + cipher_sigma_blocks;
    string statement_in_32bits = on_chain_commit;
    const int num_inputs = statement_in_8bits.length()/2 + statement_in_32bits.length()/8 + 1+1;

    VariableArray input(num_inputs, "input");

    // "1" for const one-input
    pb->val(input[0]) = readFieldElementFromHex("1");

    int input_idx = 1;
    for (int i = 0; i < statement_in_8bits.length(); i += 2)
    {
        char tmp[2];
        string str = statement_in_8bits.substr(i, i+2);
        tmp[0] = str[0];
        tmp[1] = str[1];
        pb->val(input[input_idx]) = readFieldElementFromHex(tmp);
//        cout << "input[" << input_idx << "]="  << tmp << endl;
        input_idx++;
    }

    for (int i = 0; i < statement_in_32bits.length(); i += 8) {
        char tmp[8];
        string str = statement_in_32bits.substr(i, i+8);
        for (int j = 0; j < 8; j++) {
            tmp[j] = str[j];
        }

        pb->val(input[input_idx++]) = readFieldElementFromHex(tmp);
    }

    // "1" for correct output
    pb->val(input[input_idx]) = readFieldElementFromHex("1");

    std::fstream pr("proof.raw", std::ios_base::in);
    r1cs_gg_ppzksnark_proof<libsnark::default_r1cs_gg_ppzksnark_pp> proof;
    pr >> proof;
    pr.close();

    std::fstream vkf("vk.raw", std::ios_base::in);
    r1cs_gg_ppzksnark_verification_key<libsnark::default_r1cs_gg_ppzksnark_pp> vk;
    vkf >> vk;
    vkf.close();

    const r1cs_variable_assignment<FieldT> full_assignment = get_variable_assignment_from_gadgetlib2(*pb);
    const r1cs_primary_input<FieldT> primary_input(full_assignment.begin(),full_assignment.begin() + num_inputs);

    const bool ans = r1cs_gg_ppzksnark_verifier_strong_IC<libsnark::default_r1cs_gg_ppzksnark_pp>(vk, primary_input, proof);
    printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));


}
