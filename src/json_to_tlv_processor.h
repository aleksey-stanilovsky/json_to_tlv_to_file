//
// Created by alst on 21.02.23.
//

#ifndef NXLOG_TEST_CPP_JSON_TO_TLV_PROCESSOR_H
#define NXLOG_TEST_CPP_JSON_TO_TLV_PROCESSOR_H

#include <string>
#include "tlv.h"
#include "tlv_box.h"

#define TYPE_BOOL           0x01
#define TYPE_SHORT          0x02
#define TYPE_INT            0x03
#define TYPE_LONG           0x04
#define TYPE_LONG_LONG      0x05
#define TYPE_FLOAT          0x06
#define TYPE_DOUBLE         0x07
#define TYPE_STRING         0x08
#define TYPE_OBJECT         0x09

#define TYPE_SHORT_KEY      0x0A
#define TYPE_INT_KEY        0x0B
#define TYPE_LONG_KEY       0x0C

class json_to_tlv_processor
{
public:
    explicit json_to_tlv_processor(const std::string &file_in_hash,
                                   const std::string &file_out_data,
                                   const std::string &file_out_hash );

    ~json_to_tlv_processor() = default;

    //! For printing data from file to see that it has been written properly.
    static int print_tlv_from_file(const std::string &filepath);

    //! For saving data from JSON file to tlv files - file_out_data for data itself and file_out_hash for hash table.
    int save();

private:
    //! read data from file
    int read_and_save_data() ;

    //!save tlv box to file
    static int save_box_to_file( tlv::TlvBox &box, FILE *pf );

    //!parse tlv box and prints it's data.
    static int parse_tlvbox(const tlv::TlvBox &parsedBox);

    //! save hash table to tlv file
    int hash_to_tlv();

    //! save json data to tlv file
    int json_to_tlv(char * data);

private:
    //!input file - json file
    FILE *pFile_input_data;
    //! output file for parsed json data
    FILE *pFile_output_data;
    //! output file for hash table
    FILE *pFile_output_hash;

    //! hash table
    std::unordered_map<std::string, long> hash;
    //!index for hash table. It is written instead of string keys
    long index;
    //! delimiter for separaiting records in file
    static char delim;
};

#endif //NXLOG_TEST_CPP_JSON_TO_TLV_PROCESSOR_H
