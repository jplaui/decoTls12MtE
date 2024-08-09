#include "emp-sh2pc/emp-sh2pc.h"
#include "test_util.h"
using namespace emp;
using namespace std;
#define DEBUG_INFO

void fill_vector_bit(string& hex_s, vector<Bit> &v, int party) {
    string bin = hex_to_binary(hex_s);
    std::reverse(bin.begin(), bin.end());
    for (size_t i = 0; i < bin.size(); i++) {
        v.push_back(Bit(bin[i]=='1'? true: false, party));
    }
}

void debug_print(vector<Bit> &v, int len, string name){
    Integer integer{len,0,PUBLIC};
    for (int i = 0; i < len; i++) {
        integer[i] = v[i];
    }
    string tmp = integer.reveal<string>();
    std::reverse(tmp.begin(), tmp.end());
    string tmp_hex = bin_to_hex(tmp);
    std::cout << name << tmp_hex << std::endl;
}

void reveal_out_print_vector(vector<Bit> &v, int len, string name, int party=PUBLIC){
    Integer integer{len,0,PUBLIC};
    for (int i = 0; i < len; i++) {
        integer[i] = v[i];
    }
    string tmp = integer.reveal<string>(party);
    std::reverse(tmp.begin(), tmp.end());
    string tmp_hex = bin_to_hex(tmp);
    std::cout << name << tmp_hex << std::endl;
}

void padding_to_512bits(vector<Bit> &in, vector<Bit> &padding_in, int original_len){

    int j = 0;
    for (int i = 0; i < 512 - original_len; i++) {
        padding_in.push_back(Bit(false, PUBLIC));
        j++;
    }

    for (int i = 0; i < original_len; i++) {
        padding_in.push_back(in[i]);
        j++;
    }

}

void xor_key_pad(vector<Bit> &padding_in, string single_key_pad){

    string key_pad;
    for (int i = 0; i < 64; i++) {
        key_pad += single_key_pad;
    }

    string bin_pad = hex_to_binary(key_pad);
    std::reverse(bin_pad.begin(), bin_pad.end());

    vector<Bit> key_pad_integer;

    for (int i = 0; i < 512; i++) {
        key_pad_integer.push_back(Bit(bin_pad[i] == '1'? true: false,PUBLIC));
    }

    for (int i = 0; i < 512; i++) {
        padding_in[i] ^= key_pad_integer[i];
    }

}

void compute_padding(vector<Bit>& in_256bit, vector<Bit>& out_512bit, string key_pad){
    padding_to_512bits(in_256bit, out_512bit, in_256bit.size());
    xor_key_pad(out_512bit, key_pad);
}

void hmac_setup(vector<Bit> &iv, vector<Bit>& key_mac1, vector<Bit> & key_mac2,vector<Bit> &out_256bit){
    std::string filepath = "/usr/local/include/emp-tool/circuits/files/bristol_fashion/sha256.txt";
    BristolFashion cf(filepath.c_str());
    vector<Bit> key_mac;
    for (int i = 0; i < 256; i++) {
        key_mac.push_back(key_mac1[i] ^ key_mac2[i]);
    }
    vector<Bit> inner_digest;
    compute_padding(key_mac, inner_digest, "36");
    vector<Bit> input;
    for (int i = 0; i < 512; i++ ) {
        input.push_back(inner_digest[i]);
    }

    for (int i = 0; i < 256; i++) {
        input.push_back(iv[i]);
    }

    for (int i = 1; i < 256; i++) {
        out_256bit.push_back(Bit(false, PUBLIC));
    }
    cf.compute(out_256bit.data(), input.data());
    reveal_out_print_vector(out_256bit, 256, "hash ", PUBLIC);

}

int main(int argc, char** argv) {

    vector<Bit> prover_key_mac;
    vector<Bit> verifier_key_mac;
    vector<Bit> out;
    string k_mac_p_s = "0000000000000000000000000000000000000000000000000000000000000000";
    string k_mac_v_s = "0000000000000000000000000000000000000000000000000000000000000000";
    if (argv[3] != nullptr) {
        k_mac_p_s = string(argv[3]);
    }
    if (argv[4] != nullptr) {
        k_mac_v_s = string(argv[4]);
    }

    // generate circuit for use in malicious library
    if (argc == 2 && strcmp(argv[1], "-m") == 0 ) {
        setup_plain_prot(true, "hmac-setup.txt");

        if (prover_key_mac.size() == 0) {
            fill_vector_bit(k_mac_p_s, prover_key_mac, ALICE);
        }

        if (verifier_key_mac.size() == 0) {
            fill_vector_bit(k_mac_v_s, verifier_key_mac, BOB);
        }

        string iv_s = "6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19";
        string iv_bin = hex_to_binary(iv_s);
        reverse(iv_bin.begin(), iv_bin.end());

        vector<Bit> iv;
        for(int i = 0; i < 256; i++) {
            iv.push_back(Bit(iv_bin[i] == '1'? true: false, PUBLIC));
        }

        hmac_setup(iv, prover_key_mac, verifier_key_mac, out);
        finalize_plain_prot();
        return 0;
    }

    // run computation with semi-honest model
    int port, party;
    parse_party_and_port(argv, &party, &port);
    NetIO * io = new NetIO(party==ALICE ? nullptr : "127.0.0.1", port);
    setup_semi_honest(io, party);
    if (prover_key_mac.size() == 0) {
        fill_vector_bit(k_mac_p_s, prover_key_mac, ALICE);
    }

    if (verifier_key_mac.size() == 0) {
        fill_vector_bit(k_mac_v_s, verifier_key_mac, BOB);
    }

    string iv_s = "6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19";
    string iv_bin = hex_to_binary(iv_s);
    reverse(iv_bin.begin(), iv_bin.end());

    vector<Bit> iv;
    for(int i = 0; i < 256; i++) {
        iv.push_back(Bit(iv_bin[i] == '1'? true: false, PUBLIC));
    }

    hmac_setup(iv, prover_key_mac, verifier_key_mac, out);
    delete io;
}

