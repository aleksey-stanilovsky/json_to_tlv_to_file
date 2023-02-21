#include "json_to_tlv_processor.h"

int main() {
    std::string fin_data = "test.json";
    std::string fout_data = "test.txt";
    std::string fout_hash = "hash.txt";

    json_to_tlv_processor processor(fin_data, fout_data, fout_hash);
    processor.save();

    json_to_tlv_processor::print_tlv_from_file(fout_data);
    json_to_tlv_processor::print_tlv_from_file(fout_hash);


    return 0;
}
