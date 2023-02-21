//
// Created by alst on 21.02.23.
//
#include <iostream>
#include <fstream>
#include <cstdio>
#include <cstring>
#include <limits>

#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"

#include "error_codes.h"
#include "json_to_tlv_processor.h"

char json_to_tlv_processor::delim = '$';

json_to_tlv_processor::json_to_tlv_processor(const std::string &file_in_hash,
                                             const std::string &file_out_data,
                                             const std::string &file_out_hash )
: pFile_input_data(std::fopen(file_in_hash.c_str(), "r"))
, pFile_output_data(std::fopen(file_out_data.c_str(), "wb"))
, pFile_output_hash(std::fopen(file_out_hash.c_str(), "wb"))
, hash()
, index(1)
{}


int json_to_tlv_processor::print_tlv_from_file(const std::string &filepath)
{
    const int BUFFER_SIZE = (1 * 1024 * 1024);
    unsigned char buffer[BUFFER_SIZE] = {0};

    std::fstream fp(filepath.c_str() , std::fstream::in | std::fstream::binary );
    if (fp.is_open())
    {
        while(fp.getline( (char *)buffer, BUFFER_SIZE, delim).good())
        {
            std::cout << std::endl;

            tlv::TlvBox parsedBox;
            if ( !parsedBox.Parse(buffer, static_cast<int>(fp.gcount() -1) ) ) {
                std::cout << "boxes Parse Failed !" << std::endl;
                return ERROR_PARSE_TLV;
            }

            std::cout << "box Parse Success, " << std::dec << parsedBox.GetSerializedBytes() << " bytes \n";

            parse_tlvbox(parsedBox);
        }
    }
    fp.close();
    return 0;
}

int json_to_tlv_processor::save() {
    int rc;
    if( ( rc = read_and_save_data() ) )
        return rc;

    return hash_to_tlv();
}

int json_to_tlv_processor::read_and_save_data() {
    int rc;
    static const size_t RES_SIZE = 8192;
    char res[RES_SIZE +1] = {0};

    char  *line = {nullptr};
    size_t len =  {0};

    ssize_t read;
    int pos{0};

    if (pFile_input_data == nullptr)
    {
        perror("[ERR] Could not opening the file");
        return ERROR_READ;
    }

    while (( read = getline(&line, &len, pFile_input_data) ) != -1 ) {
        if ( ( RES_SIZE - pos ) < read ) {
            snprintf(res + pos - 2, sizeof(res) - pos + 1, "%c", '}');
            printf("%s", res);

            if( ( rc = json_to_tlv(res) ) )
            {
                fclose (pFile_input_data);
                return rc;
            }

            memset(res, 0, sizeof(res));
            pos = snprintf(res, sizeof(res), "%c", '{');
        }
        pos += snprintf(res + pos, sizeof(res) - pos, "%s", line);
    }

    printf("%s", res);
    rc = json_to_tlv(res);

    fclose (pFile_input_data);
    fclose (pFile_output_data);

    return rc;
}

int json_to_tlv_processor::save_box_to_file( tlv::TlvBox &box, FILE *pf )
{
    if (!box.Serialize()) {
        std::cout << "boxes Serialize Failed !\n";
        return ERROR_PARSE_TLV;
    }

    std::cout << "boxes Serialize Success, " << box.GetSerializedBytes() << " bytes \n";

    std::fwrite( box.GetSerializedBuffer(), box.GetSerializedBytes(), 1 ,pf);
    std::putc(delim, pf);

    return 0;
}

int json_to_tlv_processor::parse_tlvbox(const tlv::TlvBox &parsedBox)
{
    std::vector<int> tlvList;
    int numTlvs = parsedBox.GetTLVList(tlvList);
    std::cout <<  "box contains " << numTlvs << " TLVs: \n";
    for ( int i = 0; i < numTlvs; i++ )
    {
        std::cout << "Tlv " << tlvList[i] << "\n";
        switch (tlvList[i]) {
            case TYPE_BOOL:
            {
                bool value;
                if (!parsedBox.GetBoolValue(TYPE_BOOL, value)) {
                    std::cout << "GetBoolValue Failed !\n";
                    return ERROR_PARSE_TLV;
                }
                std::cout << "GetBoolValue Success " << value << std::endl;
            }
                break;
            case TYPE_SHORT:
            {
                short value;
                if (!parsedBox.GetShortValue(TYPE_SHORT, value)) {
                    std::cout << "GetShortValue Failed !\n";
                    return ERROR_PARSE_TLV;
                }
                std::cout << "GetShortValue Success " << value << std::endl;
            }
                break;
            case TYPE_INT:
            {
                int value;
                if (!parsedBox.GetIntValue(TYPE_INT, value)) {
                    std::cout << "GetIntValue Failed !\n";
                    return ERROR_PARSE_TLV;
                }
                std::cout << "GetIntValue Success " << value << std::endl;
            }
                break;
            case TYPE_LONG:
            {
                long value;
                if (!parsedBox.GetLongValue(TYPE_LONG, value)) {
                    std::cout << "GetLongValue Failed !\n";
                    return ERROR_PARSE_TLV;
                }
                std::cout << "GetLongValue Success " << value << std::endl;
            }
                break;
            case TYPE_LONG_LONG:
            {
                long long value;
                if (!parsedBox.GetLongLongValue(TYPE_LONG_LONG, value)) {
                    std::cout << "GetLongLongValue Failed !\n";
                    return ERROR_PARSE_TLV;
                }
                std::cout << "GetLongLongValue Success " << value << std::endl;
            }
                break;
            case TYPE_FLOAT:
            {
                float value;
                if (!parsedBox.GetFloatValue(TYPE_FLOAT, value)) {
                    std::cout << "GetFloatValue Failed !\n";
                    return ERROR_PARSE_TLV;
                }
                std::cout << "GetFloatValue Success " << value << std::endl;
            }
                break;
            case TYPE_DOUBLE:
            {
                double value;
                if (!parsedBox.GetDoubleValue(TYPE_DOUBLE, value)) {
                    std::cout << "GetDoubleValue Failed !\n";
                    return ERROR_PARSE_TLV;
                }
                std::cout << "GetDoubleValue Success " << value << std::endl;
            }
                break;
            case TYPE_STRING:
            {
                char value[128];
                int length = 128;
                if (!parsedBox.GetStringValue(TYPE_STRING, value, length)) {
                    std::cout << "GetStringValue Failed !\n";
                    return ERROR_PARSE_TLV;
                }
                std::cout << "GetStringValue Success " << value << std::endl;
            }
                break;
            case TYPE_OBJECT:
            {
                tlv::TlvBox parsedBox2;
                if (!parsedBox.GetObjectValue(TYPE_OBJECT, parsedBox2)) {
                    std::cout << "GetObjectValue Failed !\n";
                    return ERROR_PARSE_TLV;
                }

                std::cout << "box Parse Success, " << parsedBox.GetSerializedBytes() << " bytes \n";
            }
                break;
            case TYPE_SHORT_KEY:
            {
                short value;
                if (!parsedBox.GetShortValue(TYPE_SHORT_KEY, value)) {
                    std::cout << "GetShortValue Failed !\n";
                    return ERROR_PARSE_TLV;
                }
                std::cout << "GetShortValue Success " << value << std::endl;
            }
                break;
            case TYPE_INT_KEY:
            {
                int value;
                if (!parsedBox.GetIntValue(TYPE_INT_KEY, value)) {
                    std::cout << "GetIntValue Failed !\n";
                    return ERROR_PARSE_TLV;
                }
                std::cout << "GetIntValue Success " << value << std::endl;
            }
                break;
            case TYPE_LONG_KEY:
            {
                long value;
                if (!parsedBox.GetLongValue(TYPE_LONG_KEY, value)) {
                    std::cout << "GetLongValue Failed !\n";
                    return ERROR_PARSE_TLV;
                }
                std::cout << "GetLongValue Success " << value << std::endl;
            }
                break;
            default:
                std::cout << "[ERR] troubles during parsing" << std::endl;
                break;
        }
    }
    std::cout << std::endl;
    return 0;
}

int json_to_tlv_processor::hash_to_tlv()
{
    int rc{0};

    if (pFile_output_hash != nullptr)
    {
        for(auto &couple:hash)
        {
            tlv::TlvBox box;
            box.PutStringValue(TYPE_STRING, couple.first);

            if( couple.second <=  std::numeric_limits<short>::max() && couple.second > std::numeric_limits<short>::min() )
                box.PutShortValue(TYPE_SHORT, static_cast<short>(couple.second ) );
            else if( couple.second  <= std::numeric_limits<int>::max() && couple.second  > std::numeric_limits<int>::min() )
                box.PutIntValue(TYPE_INT, static_cast<int>(couple.second ));
            else
                box.PutLongValue(TYPE_LONG, couple.second );

            if ( ( rc = save_box_to_file(box, pFile_output_hash) ) )
            {
                fclose(pFile_output_hash);
                return rc;
            }
        }
        if( pFile_output_hash != nullptr)
            fclose(pFile_output_hash);
    }
    return rc;
}

int json_to_tlv_processor::json_to_tlv(char * data){
    rapidjson::Document dock;

    if (dock.Parse(data).HasParseError()) {
        std::cout << "[ERR] json is not valid " << std::endl;
        return ERROR_PARSE;
    }

    for (auto i = dock.MemberBegin(); i != dock.MemberEnd(); ++i)
    {
        tlv::TlvBox box;

        if( !i->name.IsString() )
        {
            std::cout << "[ERR] key data type != string" << std::endl;
            return ERROR_PARSE;
        }
        //key
        hash[i->name.GetString()] = index;

        if( index <=  std::numeric_limits<short>::max() && index > std::numeric_limits<short>::min() )
            box.PutShortValue(TYPE_SHORT_KEY, static_cast<short>(index) );
        else if( index <= std::numeric_limits<int>::max() && index > std::numeric_limits<int>::min() )
            box.PutIntValue(TYPE_INT_KEY, static_cast<int>(index));
        else
            box.PutLongValue(TYPE_LONG_KEY, index);

        index++;
        //value
        if( i->value.IsString() )
        {
            box.PutStringValue(TYPE_STRING, i->value.GetString());
        }
        else if(i->value.IsBool())
        {
            box.PutBoolValue(TYPE_BOOL, i->value.GetBool());
        }
        else if(i->value.IsDouble())
        {
            box.PutDoubleValue(TYPE_DOUBLE, i->value.GetDouble());
        }
        else if(i->value.IsFloat())
        {
            box.PutFloatValue(TYPE_FLOAT, i->value.GetFloat());
        }
        else if(i->value.IsInt())
        {
            int buf = i->value.GetInt();
            if( buf <=  std::numeric_limits<short>::max() && buf > std::numeric_limits<short>::min() )
                box.PutShortValue(TYPE_SHORT, static_cast<short>(buf) );
            else
                box.PutIntValue(TYPE_INT, i->value.GetInt());
        }
        else if(i->value.IsInt64())
        {
            box.PutLongValue(TYPE_LONG, i->value.GetInt64());
        }
        else
        {
            std::cout << "[ERR] unhandled json type" << std::endl;
            return ERROR_TLV_UNH_DATA_TYPE;
        }

        save_box_to_file(box, pFile_output_data);
    }
    return 0;
}
