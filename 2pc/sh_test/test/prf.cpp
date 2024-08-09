#include "emp-sh2pc/emp-sh2pc.h"
#include "test_util.h"
using namespace emp;
using namespace std;
#define DEBUG_PRINT
//#define DEBUG_INFO


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

void concatenate_three_bitstream(vector<Bit>& first, vector<Bit>& second, vector<Bit> &third, vector<Bit> &total) {
    for (size_t i = 0; i < third.size(); i++) {
        total.push_back(third[i]);
    }
    for (size_t i = 0; i < second.size(); i++) {
        total.push_back(second[i]);
    }
    for (size_t i = 0; i < first.size(); i++) {
        total.push_back(first[i]);
    }
}

void concatenate_four_bitstream(vector<Bit>& first, vector<Bit>& second, vector<Bit> &third,
                                vector<Bit> fourth, vector<Bit> &total) {
    for (size_t i = 0; i < fourth.size(); i++) {
        total.push_back(fourth[i]);
    }
    for (size_t i = 0; i < third.size(); i++) {
        total.push_back(third[i]);
    }
    for (size_t i = 0; i < second.size(); i++) {
        total.push_back(second[i]);
    }
    for (size_t i = 0; i < first.size(); i++) {
        total.push_back(first[i]);
    }
}



void reveal_final_output(Integer &integer, int len, string name, int party) {
    string tmp = integer.reveal<string>(party);
//    std::reverse(tmp.begin(), tmp.end());
    string tmp_hex = bin_to_hex(tmp);
    std::cout << name << tmp_hex << std::endl;
}
void two_round_prf(vector<Bit> &first_iv,vector<Bit> &pre_master_secret, vector<Bit> &master_secret_label,
                   vector<Bit> &client_random, vector<Bit> & server_random, vector<Bit> &master_secret){

    vector<Bit> label_seed;
    concatenate_three_bitstream(master_secret_label, client_random, server_random, label_seed);
    debug_print(label_seed, 256+256+104, "l and seed ");
    vector<Bit> a1;
    hmac(first_iv, pre_master_secret, label_seed, a1);
    debug_print(pre_master_secret, 256, "pre: ", PUBLIC);
    debug_print(first_iv, 256, "iv: ", PUBLIC);
    debug_print(a1, 256, "a1 ");
    vector<Bit> a1_seed;
    concatenate_bitstream(a1, label_seed, a1_seed);
    vector<Bit> a2;
    hmac(first_iv, pre_master_secret, a1, a2);
    debug_print(a2, 256, "a2: ");
    vector<Bit> first_hmac;
    hmac(first_iv, pre_master_secret, a1_seed, first_hmac);
    debug_print(first_hmac, 256, "first hmac  ");
    vector<Bit> a2_seed;
    concatenate_bitstream(a2, label_seed, a2_seed);
    debug_print(a2_seed, 256+256+104, "a2_seed  ");
    vector<Bit> second_hmac;
    hmac(first_iv,pre_master_secret, a2_seed, second_hmac);
    debug_print(second_hmac, 256, "second hmac  ");
    vector<Bit> total_master_secret;
    concatenate_bitstream(first_hmac, second_hmac, total_master_secret);
//    Integer out(384,0,PUBLIC);
//    int total_len = total_master_secret.size();

//    int j = 0;
//    for (int i = total_len-1-383; i < total_len-1; i++) {
//        out[j] = total_master_secret[i];
//        j++;
//    }
//    integer_to_vector(out, master_secret, 0);
    for (int i = 0; i < 384; i++) {
        master_secret.push_back(total_master_secret[i+128]);
    }
    debug_print(master_secret,384, "master secret: ");

}

void key_expansion_prf(vector<Bit> &first_iv,vector<Bit> &master_secret, vector<Bit> &key_expansion_label,
                       vector<Bit> &client_random, vector<Bit> & server_random, vector<Bit> & key_expansion){

    vector<Bit> label_seed;
    concatenate_three_bitstream(key_expansion_label, server_random, client_random, label_seed);
    debug_print(label_seed, 256+256+104, " ke l& seed ");
    vector<Bit> a1;
    hmac(first_iv, master_secret, label_seed, a1);
    debug_print(a1, 256, "a1 ");
    vector<Bit> a1_seed;
    concatenate_bitstream(a1, label_seed, a1_seed);
    vector<Bit> a2;
    hmac(first_iv, master_secret, a1, a2);
    debug_print(a2, 256, "a2: ");
    vector<Bit> first_hmac;
    hmac(first_iv, master_secret, a1_seed, first_hmac);
    debug_print(first_hmac, 256, "first hmac  ");
    vector<Bit> a2_seed;
    concatenate_bitstream(a2, label_seed, a2_seed);
    debug_print(a2_seed, 256+256+104, "a2_seed  ");
    vector<Bit> second_hmac;
    hmac(first_iv, master_secret, a2_seed, second_hmac);
    debug_print(second_hmac, 256, "second hmac  ");

    vector<Bit> a3;
    hmac(first_iv, master_secret, a2, a3);
    debug_print(a3, 256, "a3  ");
    vector<Bit> a3_seed;
    concatenate_bitstream(a3, label_seed, a3_seed);
    vector<Bit> third_mac;
    hmac(first_iv, master_secret, a3_seed, third_mac);
    debug_print(third_mac, 256, "third mac  ");
    vector<Bit> a4;
    hmac(first_iv, master_secret, a3, a4);
    vector<Bit> a4_seed;
    concatenate_bitstream(a4, label_seed, a4_seed);
    vector<Bit> fourth_mac;
    hmac(first_iv, master_secret, a4_seed, fourth_mac);
    debug_print(fourth_mac, 256, "a4  ");
    vector<Bit> key_material;
    concatenate_four_bitstream(first_hmac, second_hmac,third_mac, fourth_mac, key_material);

    for (int i = 0; i < 1024; i++) {
        key_expansion.push_back(key_material[i]);
    }

}


void gen_random_and_reveal(vector<Bit> &first_iv,vector<Bit> &key_expansion, vector<Bit> &master_secret) {

    const int macLen = 256;
    const int keyLen = 128;
    const int ivLen = 128;
    Integer r_k{256,0, PUBLIC};
    Integer r_m1{256,0,PUBLIC};
//    Integer r_m2{256, 0, PUBLIC};
    Integer sha256_input{512+256,0,PUBLIC};
    for (int i = 0; i < 384; i++) {
        sha256_input[i] = master_secret[i];
    }
    for (int i = 384; i < 256+512; i++) {
        sha256_input[i] = first_iv[i];
    }
    std::string filepath = "/usr/local/include/emp-tool/circuits/files/bristol_fashion/sha256.txt";
    BristolFashion cf(filepath.c_str());
    cf.compute(r_k.bits.data(),sha256_input.bits.data());

    for (int i = 0; i < 512; i++) {
        sha256_input[i] = key_expansion[macLen*2-1-i];
    }
    cf.compute(r_m1.bits.data(),sha256_input.bits.data());
//    for (int i = 0; i < 256; i++) {
//        sha256_input[i] = r_m1[i];
//    }
//    cf.compute(r_m2.bits.data(), sha256_input.bits.data());

    Integer r_m{384,0,PUBLIC};
    for (int i = 0; i < 256; i++) {
        r_m[i] = r_m1[i];
    }
    for (int i = 0; i < 128; i++) {
        r_m[i+256] = r_m1[i];
    }
    Integer mac_client{macLen,0,PUBLIC};
    Integer mac_server{macLen,0,PUBLIC};
    Integer key_client{keyLen,0,PUBLIC};
    Integer key_server{keyLen,0,PUBLIC};
    Integer iv_client{ivLen,0,PUBLIC};
    Integer iv_server{ivLen,0,PUBLIC};
    int count = 1023;
    for (int i = 0; i < macLen; i++ ) {
        mac_client[i] = key_expansion[count--];
    }

    for (int i = 0; i < macLen; i++) {
        mac_server[i] = key_expansion[count--];
    }

    for (int i = 0; i < keyLen; i++) {
        key_client[i] = key_expansion[count--];
    }
    for (int i = 0; i < keyLen; i++) {
        key_server[i] = key_expansion[count--];
    }

    for (int i = 0; i < ivLen; i++) {
        iv_client[i] = key_expansion[count--];
    }

    for (int i = 0; i < ivLen; i++) {
        iv_server[i] = key_expansion[count--];
    }
    Integer xor_mac_server = r_k ^ mac_server;
    reveal_final_output(xor_mac_server, macLen, "xor mac server ", BOB);
    reveal_final_output(key_client, keyLen,"key client ", ALICE);
    reveal_final_output(key_server, keyLen, "key server ", ALICE);
    reveal_final_output(iv_client, ivLen, "iv client ", ALICE);
    reveal_final_output(iv_server, ivLen, "iv server ", ALICE);
    reveal_final_output(r_k, macLen, "r_k ", ALICE);
    Integer xor_mac_client = r_k ^ mac_client;
    reveal_final_output(xor_mac_client, macLen, "xor_mac_client ", BOB);
    Integer master_secret_integer{384,0,PUBLIC};
    for (int i = 0; i < 384; i++) {
        master_secret_integer[i] = master_secret[383-i];
    }
    Integer xor_master_secret = r_m ^ master_secret_integer;
    reveal_final_output(r_m, 384, "r_m ", ALICE);
    reveal_final_output(xor_master_secret, 384, "xor_master_secret ", BOB);

}




void add_mod(vector<Bit> & secret1, vector<Bit> &secret2, vector<Bit> &prime, vector<Bit> &sum_256bits) {

    Integer a(260, 0, PUBLIC);
    Integer b(260, 0, PUBLIC);
    Integer p(260, 0, PUBLIC);
    vector_to_integer(secret1,a);
    vector_to_integer(secret2, b);
    vector_to_integer(prime, p);

    Integer sum = (a + b) % prime;
    integer_to_vector(sum, sum_256bits, 4);
    debug_print(sum_256bits, 256, "S1+S2: ", PUBLIC);
}

void key_derivation_2pc(vector<Bit> &first_iv, vector<Bit> &secret1, vector<Bit> &secret2, vector<Bit> &client_random, vector<Bit> &server_random){
    vector<Bit> pre_master_secret;
    vector<Bit> master_secret;
    vector<Bit> key_expansion_label;
    vector<Bit> master_secret_label;
    vector<Bit> prime;
    vector<Bit> sum_256bits;
    vector<Bit> key_expansion;


    if (prime.size() == 0) {
        string p = "0ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
        fill_vector_bit(p, prime, PUBLIC);
    }
    if (master_secret_label.size() == 0) {
        string msl = "6d617374657220736563726574";
        fill_vector_bit(msl, master_secret_label, PUBLIC);
    }

    if (key_expansion_label.size() == 0) {
        string msl = "6b657920657870616e73696f6e";
        fill_vector_bit(msl, key_expansion_label, PUBLIC);
    }
    add_mod(secret1, secret2, prime, sum_256bits);
    two_round_prf(first_iv, sum_256bits, master_secret_label, client_random, server_random, master_secret);
    key_expansion_prf(first_iv, master_secret, key_expansion_label, client_random, server_random, key_expansion);
    gen_random_and_reveal(first_iv, key_expansion,master_secret);
}



int main(int argc, char** argv) {
    vector<Bit> client_random;
    vector<Bit>  server_random;
    vector<Bit> secret1;
    vector<Bit> secret2;
    string s1 = "01541295a24f71af96d95588f9352c472ff20e5a89806538febd62678abc989d9";
//    string s1 = "06f50959580ce939dffb6bf756dfb5d178df5e0133d4fb0c45e6807d39ed281b9";
    string s2 = "066ea84cec336e071b11c03854b8199107a01fa08695fa6cb9067df6a2841234a";
//    string s2 = "0e0957aab86aa0ed70dd3d9c4c6b91438016079a055bba3e1eabeb7a7a5468b18";
    string crandom = "1bf742127a6712a87a245ba16e6852a936e44bbe92919ca0d96ce1394377089e";
//    string crandom = "0c4191877ef4cf60310964841f7d548ad8b06dc3a572d9e431c002ede10f0a17";
    string srandom = "2fee6471a78b17514a68ce7d0543d6866976fecc7fda43df9e01ecec729f1316";
//    string srandom = "5ec5597540c945f5f084378bd79c70757bd869bf5ba8df434a2e7871a519630f";
//
    if (argv[3] != nullptr) {
        s1 = string(argv[3]);
    }
    if (argv[4] != nullptr) {
        s2 = string(argv[4]);
    }
    if (argv[5] != nullptr) {
        crandom = string(argv[5]);
    }
    if (argv[6] != nullptr) {
        srandom = string(argv[6]);
    }
    // generate circuit for use in malicious library
    if (argc == 2 && strcmp(argv[1], "-m") == 0 ) {
        setup_plain_prot(true, "prf.txt");
        string iv = "6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19";
        string iv_bin = hex_to_binary(iv);
        reverse(iv_bin.begin(), iv_bin.end());
        vector<Bit> first_iv;
        for(int i = 0; i < 256; i++) {
            first_iv.push_back(Bit(iv_bin[i] == '1'? true: false, PUBLIC ));
        }
        if (secret1.size() == 0) {
            fill_vector_bit(s1, secret1, ALICE);
            debug_print(secret1, 256, "S1 ", ALICE);
        }

        if (secret2.size() == 0) {

            fill_vector_bit(s2, secret2, BOB);
            debug_print(secret2, 256, "S2 ", BOB);
        }
        if (client_random.size() == 0) {

            fill_vector_bit(crandom, client_random, ALICE);
            debug_print(client_random, 256, "crand ", ALICE);
        }
        if (server_random.size() == 0) {

            fill_vector_bit(srandom, server_random, BOB);
            debug_print(server_random, 256, "srand ", BOB);
        }
        key_derivation_2pc(first_iv, secret1, secret2, client_random, server_random);
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
    if (secret1.size() == 0) {
        fill_vector_bit(s1, secret1, ALICE);
        debug_print(secret1, 256, "S1 ", ALICE);
    }

    if (secret2.size() == 0) {
        fill_vector_bit(s2, secret2, BOB);
        debug_print(secret2, 256, "S2 ", BOB);
    }
    if (client_random.size() == 0) {
        fill_vector_bit(crandom, client_random, ALICE);
        debug_print(client_random, 256, "crand ", ALICE);
    }
    if (server_random.size() == 0) {
        fill_vector_bit(srandom, server_random, BOB);
        debug_print(server_random, 256, "srand ", BOB);
    }

    key_derivation_2pc(first_iv, secret1, secret2, client_random, server_random);
    delete io;
}


