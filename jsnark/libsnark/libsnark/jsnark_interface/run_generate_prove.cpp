#include <string>
#include <iostream>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include "CircuitReader.hpp"
#include "libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp"


int main(int argc, char* argv[]) {
    libff::start_profiling();
    gadgetlib2::initPublicParamsFromDefaultPp();
    gadgetlib2::GadgetLibAdapter::resetVariableIndex();
    ProtoboardPtr pb = gadgetlib2::Protoboard::create(gadgetlib2::R1P);

    int inputStartIndex = 0;

    // Read the circuit, evaluate, and translate constraints
    CircuitReader reader(argv[1 + inputStartIndex], argv[2 + inputStartIndex], pb);
    r1cs_constraint_system<FieldT> cs = get_constraint_system_from_gadgetlib2(*pb);
    const r1cs_variable_assignment<FieldT> full_assignment = get_variable_assignment_from_gadgetlib2(*pb);
    cs.primary_input_size = reader.getNumInputs() + reader.getNumOutputs();
    cs.auxiliary_input_size = full_assignment.size() - cs.num_inputs();

    auto keypair = r1cs_gg_ppzksnark_generator<libsnark::default_r1cs_gg_ppzksnark_pp>(cs);
    std::fstream vk("vk.raw", std::ios_base::out);
    vk << keypair.vk;
    vk.close();

    // extract primary and auxiliary input
    const r1cs_primary_input<FieldT> primary_input(full_assignment.begin(), full_assignment.begin() + cs.num_inputs());
    const r1cs_auxiliary_input<FieldT> auxiliary_input(full_assignment.begin() + cs.num_inputs(), full_assignment.end());

    assert(cs.is_satisfied(primary_input, auxiliary_input));

    r1cs_example<FieldT> example(cs, primary_input, auxiliary_input);
    auto proof = r1cs_gg_ppzksnark_prover<libsnark::default_r1cs_gg_ppzksnark_pp>(keypair.pk, primary_input, auxiliary_input);


    std::fstream pr("proof.raw", std::ios_base::out);
    pr << proof;
    pr.close();

    return 0;
}
