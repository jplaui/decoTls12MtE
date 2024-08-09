#include "emp-sh2pc/emp-sh2pc.h"
#include "test_util.h"
using namespace emp;
using namespace std;
#define DEBUG_PRINT


void vector_to_integer(vector<Bit> &v,Integer &out) {
    int len = v.size();
    for (int i = 0; i < len; i++) {
        out[i] = v[i];
    }
}

void integer_to_vector(Integer &in, vector<Bit> &v, int remove_bit_len) {
    int len = in.size();
    for (int i = 0; i < len-remove_bit_len; i++) {
        v.push_back(in[i]);
    }
}

void debug_print(vector<Bit> &v, int len, string name, int party=PUBLIC){
#ifdef DEBUG_PRINT
//    Integer integer{len,0,PUBLIC};
//    for (int i = 0; i < len; i++) {
//        integer[i] = v[i];
//    }
//
//    string tmp = integer.reveal<string>(party);
//    std::reverse(tmp.begin(), tmp.end());
//    string tmp_hex = bin_to_hex(tmp);
//    std::cout << name << tmp_hex << std::endl;
#endif
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
//    debug_print(out_512bit, 512, "after extend: ", PUBLIC);
    xor_key_pad(out_512bit, key_pad);
//    debug_print(in_256bit, 256, "after extend: ", PUBLIC);

}

void concatenate_bitstream(vector<Bit>& first, vector<Bit>& second, vector<Bit> &total) {
    for (size_t i = 0; i < second.size(); i++) {
        total.push_back(second[i]);
    }
    for(size_t i = 0; i < first.size(); i++) {
        total.push_back(first[i]);
    }

}



void hmac(vector<Bit> &first_iv,vector<Bit> &key, vector<Bit> &message, vector<Bit> &total_hmac_out256bit){

    vector<Bit> ipad_out_512bit;
    compute_padding(key, ipad_out_512bit, "36");  //KEY XOR IPAD
//    debug_print(ipad_out_512bit, 512, "ipadout: ");
    vector<Bit> con_bitstream;

    concatenate_bitstream(ipad_out_512bit, message, con_bitstream);
    vector<Bit> chain_sha256_out_256bit;

    chainsha256(con_bitstream, first_iv,chain_sha256_out_256bit);  //HASH(key xor ipad || m)
    vector<Bit> opad_out_512bit;
    compute_padding(key, opad_out_512bit, "5c");  //KEY XOR opad
    vector<Bit> con_bitstream_total;
    concatenate_bitstream(opad_out_512bit, chain_sha256_out_256bit, con_bitstream_total);
    chainsha256(con_bitstream_total, first_iv,total_hmac_out256bit);

}

void fill_vector_bit(string& hex_s, vector<Bit> &v, int party) {
    string bin = hex_to_binary(hex_s);
    std::reverse(bin.begin(), bin.end());
    for (size_t i = 0; i < bin.size(); i++) {
        v.push_back(Bit(bin[i]=='1'? true: false, party));
    }
}


void reveal_final_output(Integer &integer, int len, string name, int party) {
    string tmp = integer.reveal<string>(party);
//    std::reverse(tmp.begin(), tmp.end());
    string tmp_hex = bin_to_hex(tmp);
    std::cout << name << tmp_hex << std::endl;
}

void server_finished_prf(vector<Bit> &first_iv,vector<Bit> &p_master_secret, vector<Bit> &v_master_secret,
                         vector<Bit> &server_finished_label, vector<Bit> &hash, vector<Bit> & verify_data){

    vector<Bit> master_secret;
    for (int i = 0; i < 384; i++) {
        master_secret.push_back(p_master_secret[i] ^ v_master_secret[i]);
    }
    debug_print(master_secret, 384, "master secret ");
    vector<Bit> label_seed;
    debug_print(server_finished_label, 120, "cfl ");
    debug_print(hash, 256, "hash ");
    concatenate_bitstream(server_finished_label, hash, label_seed);
    debug_print(label_seed, 256+120, "cf l& hash ");
    vector<Bit> a1;
    hmac(first_iv, master_secret, label_seed, a1);
    debug_print(a1, 256, "a1 ");
    vector<Bit> a1_seed;
    concatenate_bitstream(a1, label_seed, a1_seed);
    vector<Bit> first_hmac;
    hmac(first_iv, master_secret, a1_seed, first_hmac);
    debug_print(first_hmac, 256, "first hmac  ");

    for (int i = 0; i < 96; i++) {
        verify_data.push_back(first_hmac[i+256-96]);
    }
    reveal_out_print_vector(verify_data,96, "verify data ", PUBLIC);
}

void run_server_finished_prf(vector<Bit> &first_iv, vector<Bit> &p_master_secret, vector<Bit> &v_master_secret,
                             vector<Bit> &hash, vector<Bit> &verify_data){

    vector<Bit> server_finished_label;
    if (server_finished_label.size() == 0) {
        string cfl = "7365727665722066696e6973686564";
        fill_vector_bit(cfl, server_finished_label, PUBLIC);
    }
    server_finished_prf(first_iv, p_master_secret, v_master_secret,
                        server_finished_label, hash, verify_data);

}



int main(int argc, char** argv) {
    vector<Bit> prover_master_secret;
    vector<Bit> verifier_master_secret;
    vector<Bit> verify_data;
    vector<Bit> server_hash;
//    string K_mac_p_s = "6424B977EB6C9EC757EB02B4A33DAA9907D43428353292EB84A70C8F8EE277D36424B977EB6C9EC757EB02B4A33DAA99";
    string K_mac_p_s = "52B9065E9E5DE1877861CC7FD875E42101EC50F2F39A47B541F9A1D99BD2CA2A52B9065E9E5DE1877861CC7FD875E421";
//    string K_mac_v_s = "0364BC1D8B8E3D517E2786714F11C65726A3D47AD560C3F0950D5C9DE6331CEB232850CD34643FB2A53D1E200BE1DF7B";
//    string K_mac_v_s = "400B8130A55C3A6B43009696F8C821B4AFC21C33876F9060E56D333CAD5AD65C5372F52C22D72ED99E8E2537B5CC7A53";
    string K_mac_v_s = "ADA6141006FAD03F7BDBE16BBA67BCB0A7205D36D275D9173F6E8A4CCFF0E3C043CA000915E3F5265CFDF73D9B6BCF70";
//    string server_hash_s = "50ba1d7251e8c17689cc8963e821cc544038823c46eafa02cb4ac8b0b3b3c460";
    string server_hash_s = "697347ff9f6c0341a5d19e3be7707b41fe765527a47f8136b4349cc9559820e0";
//    string server_hash_s = "0000000000000000000000000000000000000000000000000000000000000000";
    if (argv[3] != nullptr) {
        K_mac_p_s = string(argv[3]);
    }
    if (argv[4] != nullptr) {
        K_mac_v_s = string(argv[4]);
    }
    if (argv[5] != nullptr) {
        server_hash_s = string(argv[5]);
    }

    if (argc == 2 && strcmp(argv[1], "-m") == 0 ) {
        setup_plain_prot(true, "prf_server_finished.txt");
        string iv = "6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19";
        string iv_bin = hex_to_binary(iv);
        reverse(iv_bin.begin(), iv_bin.end());
        vector<Bit> first_iv;
        for(int i = 0; i < 256; i++) {
            first_iv.push_back(Bit(iv_bin[i] == '1'? true: false, PUBLIC ));
        }
        if (prover_master_secret.size() == 0) {
            fill_vector_bit(K_mac_p_s, prover_master_secret, ALICE);
            debug_print(prover_master_secret, 384, "K_mac_p ", ALICE);
        }

        if (verifier_master_secret.size() == 0) {

            fill_vector_bit(K_mac_v_s, verifier_master_secret, BOB);
            debug_print(verifier_master_secret, 384, "K_mac_v ", BOB);
        }
        if (server_hash.size() == 0) {

            fill_vector_bit(server_hash_s, server_hash, ALICE);
            debug_print(server_hash, 256, "hash ", ALICE);
        }


        run_server_finished_prf(first_iv, prover_master_secret, verifier_master_secret,
                                server_hash, verify_data);
        finalize_plain_prot();
        return 0;
    }

    // run computation with semi-honest model
    int port, party;
    parse_party_and_port(argv, &party, &port);


    NetIO * io = new NetIO(party==ALICE ? nullptr : "127.0.0.1", port);
    setup_semi_honest(io, party);
    string iv = "6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19";
    string iv_bin = hex_to_binary(iv);
    reverse(iv_bin.begin(), iv_bin.end());
    vector<Bit> first_iv;
    for(int i = 0; i < 256; i++) {
        first_iv.push_back(Bit(iv_bin[i] == '1'? true: false, PUBLIC ));
    }
    if (prover_master_secret.size() == 0) {
        fill_vector_bit(K_mac_p_s, prover_master_secret, ALICE);
        debug_print(prover_master_secret, 384, "K_mac_p ", ALICE);
    }

    if (verifier_master_secret.size() == 0) {

        fill_vector_bit(K_mac_v_s, verifier_master_secret, BOB);
        debug_print(verifier_master_secret, 384, "K_mac_v ", BOB);
    }
    if (server_hash.size() == 0) {

        fill_vector_bit(server_hash_s, server_hash, ALICE);
        debug_print(server_hash, 256, "hash ", ALICE);
    }


    run_server_finished_prf(first_iv, prover_master_secret, verifier_master_secret,
                            server_hash, verify_data);
    delete io;
}
