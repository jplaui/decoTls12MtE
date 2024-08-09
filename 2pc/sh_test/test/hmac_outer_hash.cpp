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
//    Integer integer{len,0,PUBLIC};
//    for (int i = 0; i < len; i++) {
//        integer[i] = v[i];
//    }
//    string tmp = integer.reveal<string>();
//    std::reverse(tmp.begin(), tmp.end());
//    string tmp_hex = bin_to_hex(tmp);
//    std::cout << name << tmp_hex << std::endl;
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



int find_min_k(int l, int nr_blk){
    int k;
    int block_count = nr_blk;
    do {
        k = 512* (nr_blk+1) - l - 64 - 1;
        block_count++;
    } while(k < 0);
    return k;
}

std::unique_ptr<int []> calc_in_array_len(int len){
    int nr_blk = len / 512;
    int padding_k = find_min_k(len, nr_blk);
    int total_in_bits = len + 1 + 64 + padding_k;
    int integer_len = total_in_bits / 512;
    std::unique_ptr<int []> ret(new int[2]);
    ret[0] = integer_len;
    ret[1] = padding_k;
    return ret;
}

void padding(vector<Bit> &in1, int len, Integer *inp, int padding_k){
    Integer zerobit(1, 0, PUBLIC);
    Integer onebit(1,1,PUBLIC);
    string len_bin = bitset<64>(len).to_string();
    reverse(len_bin.begin(), len_bin.end());

    int i = 0, j = 0;
    int tmp_j = 0;
    while (j < 64) {
        inp[0][j] = len_bin[j] == '1' ? onebit[0]: zerobit[0];
        j++;
    }
    while (j < padding_k + 64) {
        tmp_j = j % 512;
        if (tmp_j == 0) {
            i++;
        }
        inp[i][tmp_j] = zerobit[0];
        j++;
        tmp_j++;
    }
    inp[i][tmp_j] = onebit[0];
    j++;
    int count = 0;
    while (j < len + padding_k + 65){
        tmp_j = j % 512;
        if (tmp_j == 0) {
            i++;
        }
        inp[i][tmp_j] = in1[count];
        count++;
        j++;
    }
}

void chainsha256(vector<Bit>& in1, vector<Bit> & in2,vector<Bit> &out_256bit){

    int input_length = in1.size();
    Integer inp(512+256,0, PUBLIC);

    std::unique_ptr<int[]> calc_len_arr = calc_in_array_len(input_length);
    int in_buf_len = calc_len_arr[0];
    int padding_k = calc_len_arr[1];

    Integer in[in_buf_len];
    for (int i = 0; i < in_buf_len; i++) {
        in[i] = Integer(512, 0,PUBLIC);
    }

    padding(in1, input_length, in, padding_k);
    Integer out[in_buf_len+1];
    for (int i = in_buf_len; i >=0; i--) {
        out[i] = Integer(256, 0, PUBLIC);
    }

    std::string filepath = "/usr/local/include/emp-tool/circuits/files/bristol_fashion/sha256.txt";
    BristolFashion cf(filepath.c_str());

    for (int i = 0; i < 256; i++) {
        out[in_buf_len][i] = in2[i];
    }

    for (int i = in_buf_len -1; i >= 0; i--) {
        for (int j = 0; j < 512; j++) {
            inp[j] = in[i][j];
        }
        for (int j = 0; j < 256; j++) {
            inp[j+512] = out[i+1][j];
        }
        cf.compute(out[i].bits.data(), inp.bits.data());
    }
    string check_output = "c60416184eca4d0e84133ddaa1adde70fada3f34226ff712ed00886b9dfcc411";  // add sum input

    for (int i = 0; i < 256; i++) {
        out_256bit.push_back(out[0][i]);
    }
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

void concatenate_bitstream(vector<Bit>& first, vector<Bit>& second, vector<Bit> &total) {
    for (size_t i = 0; i < second.size(); i++) {
        total.push_back(second[i]);
    }
    for(size_t i = 0; i < first.size(); i++) {
        total.push_back(first[i]);
    }

}


void hmac_outer_hash(vector<Bit> &iv, vector<Bit>& key_mac1, vector<Bit> & key_mac2, vector<Bit> &innerHash,vector<Bit> &out_256bit){

    vector<Bit> key_mac;
    for (int i = 0; i < 256; i++) {
        key_mac.push_back(key_mac1[i] ^ key_mac2[i]);
    }
    vector<Bit> outer_digest;
    compute_padding(key_mac, outer_digest, "5c");
    debug_print(outer_digest, 512, "outer_digest ");
    vector<Bit> total_m;
    concatenate_bitstream(outer_digest, innerHash, total_m);
    debug_print(total_m,512+256, "total_m ");

    chainsha256(total_m,iv, out_256bit);
    reveal_out_print_vector(out_256bit, 256, "outerHash ", ALICE);
}

int main(int argc, char** argv) {

    vector<Bit> prover_key_mac;
    vector<Bit> verifier_key_mac;
    vector<Bit> out;
    vector<Bit> message;
    string k_mac_p_s = "0000000000000000000000000000000000000000000000000000000000000000";
    string k_mac_v_s = "0000000000000000000000000000000000000000000000000000000000000000";
    string m = "0000000000000000000000000000000000000000000000000000000000000000";
    if (argv[3] != nullptr) {
        k_mac_p_s = string(argv[3]);
    }
    if (argv[4] != nullptr) {
        k_mac_v_s = string(argv[4]);
    }
    if (argv[5] != nullptr) {
        m = string(argv[5]);
    }

    // generate circuit for use in malicious library
    if (argc == 2 && strcmp(argv[1], "-m") == 0 ) {
        setup_plain_prot(true, "hmac-outer-hash.txt");

        if (prover_key_mac.size() == 0) {
            fill_vector_bit(k_mac_p_s, prover_key_mac, ALICE);
        }

        if (verifier_key_mac.size() == 0) {
            fill_vector_bit(k_mac_v_s, verifier_key_mac, BOB);
        }
        if(message.size() == 0) {
            fill_vector_bit(m, message, ALICE);
        }

        string iv_s = "6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19";
        string iv_bin = hex_to_binary(iv_s);
        reverse(iv_bin.begin(), iv_bin.end());

        vector<Bit> iv;
        for(int i = 0; i < 256; i++) {
            iv.push_back(Bit(iv_bin[i] == '1'? true: false, PUBLIC));
        }

        debug_print(message, 256, "m ");
        hmac_outer_hash(iv, prover_key_mac, verifier_key_mac, message , out);
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
    if(message.size() == 0) {
        fill_vector_bit(m, message, ALICE);
    }

    string iv_s = "6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19";
    string iv_bin = hex_to_binary(iv_s);
    reverse(iv_bin.begin(), iv_bin.end());

    vector<Bit> iv;
    for(int i = 0; i < 256; i++) {
        iv.push_back(Bit(iv_bin[i] == '1'? true: false, PUBLIC));
    }

    debug_print(message, 256, "m ");
    hmac_outer_hash(iv, prover_key_mac, verifier_key_mac, message , out);
    delete io;
}



