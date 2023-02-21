/*
 *  COPYRIGHT NOTICE  
 *  Copyright (C) 2015, Jhuster, All Rights Reserved
 *  Author: Jhuster(lujun.hust@gmail.com)
 *  
 *  https://github.com/Jhuster/TLV
 *   
 *  This library is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published
 *  by the Free Software Foundation; either version 2.1 of the License, 
 *  or (at your option) any later version.
 */
#include <string.h>
#if (defined _WIN32) || (defined _WIN64)
#include <Winsock2.h>
#else
#include <arpa/inet.h>
#endif //windows
#include "tlv.h"
#include "tlv_box.h"

#if (defined _WIN32) || (defined _WIN64)
#pragma comment(lib, "wsock32.lib")
#endif //windows

//#define htonll(x) ((((uint64_t)htonl(x)) << 32) + htonl((x) >> 32))
#define htonll(x) ((1==htonl(1)) ? (x) : (((uint64_t)htonl((x) & 0xFFFFFFFFUL)) << 32) | htonl((uint32_t)((x) >> 32)))
#define ntohll(x) ((1==ntohl(1)) ? (x) : (((uint64_t)ntohl((x) & 0xFFFFFFFFUL)) << 32) | ntohl((uint32_t)((x) >> 32)))

static float swapFloat( float f )  //assumes sender & receiver use same float format, such as IEEE-754
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    union { float f; int i; } u32; 
    u32.f = f;
    u32.i = htonl(u32.i);
    return u32.f;
#else
    return f;
#endif
}

static double swapDouble( double d )  //assumes sender & receiver use same double format, such as IEEE-754
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    union { double d; int i[2]; } u64;  //used i[2] instead of long long since some compilers don't support long long
    u64.d = d;
    int temp = htonl(u64.i[1]);
    u64.i[1] = htonl(u64.i[0]);
    u64.i[0] = temp;
    return u64.d;
#else
    return d;
#endif
}

namespace tlv
{

TlvBox::TlvBox() : mSerializedBuffer(nullptr), mSerializedBytes(0)
{

}

TlvBox::~TlvBox()
{
    if (mSerializedBuffer != nullptr) {
        delete[] mSerializedBuffer;
        mSerializedBuffer = nullptr;
    }

    for(auto & item : mTlvMap) {
        delete item.second;
    }

    mTlvMap.clear();
}

bool TlvBox::Serialize()
{
    if (mSerializedBuffer != nullptr) {
        return false;
    }

    int offset = 0;
    mSerializedBuffer = new unsigned char[mSerializedBytes];

    for(auto iterator=mTlvMap.begin(); iterator != mTlvMap.end(); iterator++) {
        int type = htonl(iterator->second->GetType());
        memcpy(mSerializedBuffer+offset, &type, sizeof(int));
        offset += sizeof(int);        
        int length = iterator->second->GetLength();
        int nwlength = htonl(length);
        memcpy(mSerializedBuffer+offset, &nwlength, sizeof(int));
        offset += sizeof(int);
        memcpy(mSerializedBuffer+offset, iterator->second->GetValue(), length);
        offset += length;
    }

    return true;
}

bool TlvBox::Parse(const unsigned char *buffer, int buffersize)
{
    if (mSerializedBuffer != nullptr || buffer == nullptr) {
        return false;
    }

    unsigned char *cached = new unsigned char[buffersize];
    memcpy(cached, buffer, buffersize);

    int offset = 0;
    while (offset < buffersize) {
        int type = ntohl((*(int *)(cached + offset)));
        offset += sizeof(int);
        int length = ntohl((*(int *)(cached + offset)));
        offset += sizeof(int);
        PutValue(new Tlv(type, cached + offset, length));
        offset += length;
    }

    mSerializedBuffer = cached;
    mSerializedBytes = buffersize;

    return true;
}

unsigned char * TlvBox::GetSerializedBuffer() const
{
    return mSerializedBuffer;
}

int TlvBox::GetSerializedBytes() const
{
    return mSerializedBytes;
}

bool TlvBox::PutNoValue(int type)
{
    if (mSerializedBuffer != nullptr) {
        return false;
    }
    return PutValue(new Tlv(type));
}

bool TlvBox::PutValue(Tlv *value)
{
    auto itor = mTlvMap.find(value->GetType());
    if (itor != mTlvMap.end()) {
        Tlv *prevTlv = itor->second;
        mSerializedBytes = mSerializedBytes - (sizeof(int) * 2 + prevTlv->GetLength());
        delete itor->second;
        itor->second = value;
    } else {
        mTlvMap.insert(std::pair<int, Tlv*>(value->GetType(), value));
    }

    mSerializedBytes += (sizeof(int) * 2 + value->GetLength());
    return true;
}

bool TlvBox::PutBoolValue(int type, bool value)
{
    if (mSerializedBuffer != nullptr) {
        return false;
    }
    return PutValue(new Tlv(type, value));
}

bool TlvBox::PutCharValue(int type, char value)
{
    if (mSerializedBuffer != nullptr) {
        return false;
    }
    return PutValue(new Tlv(type, value));
}

bool TlvBox::PutShortValue(int type, short value)
{
    if (mSerializedBuffer != nullptr) {
        return false;
    }
    auto i = static_cast<short>(htons(value));
    return PutValue(new Tlv(type, i));
}

bool TlvBox::PutIntValue(int type, int value)
{
    if (mSerializedBuffer != nullptr) {
        return false;
    }
    int nwvalue = static_cast<int>(htonl(value));
    return PutValue(new Tlv(type, nwvalue));
}

bool TlvBox::PutLongValue(int type, long value)
{
    if (mSerializedBuffer != nullptr) {
        return false;
    }
    long nwvalue = htonl(value);
    return PutValue(new Tlv(type, nwvalue));
}

bool TlvBox::PutLongLongValue(int type, long long value)
{
    if (mSerializedBuffer != nullptr) {
        return false;
    }
    long long nwvalue = htonll(value);
    return PutValue(new Tlv(type, nwvalue));
}

bool TlvBox::PutFloatValue(int type, float value)
{
    if (mSerializedBuffer != nullptr) {
        return false;
    }
    float nwvalue = swapFloat(value);
    return PutValue(new Tlv(type, nwvalue));
}

bool TlvBox::PutDoubleValue(int type, double value)
{
    if (mSerializedBuffer != nullptr) {
        return false;
    }
    double nwvalue = swapDouble(value);
    return PutValue(new Tlv(type, nwvalue));
}

bool TlvBox::PutStringValue(int type, char *value)
{
    if (mSerializedBuffer != nullptr) {
        return false;
    }
    return PutValue(new Tlv(type, value));
}

bool TlvBox::PutStringValue(int type, const std::string &value)
{
    if (mSerializedBuffer != nullptr) {
        return false;
    }
    return PutValue(new Tlv(type, value));
}

bool TlvBox::PutBytesValue(int type, unsigned char *value, int length)
{
    if (mSerializedBuffer != nullptr) {
        return false;
    }
    return PutValue(new Tlv(type, value, length));
}

bool TlvBox::PutObjectValue(int type, const TlvBox& value)
{
    if (mSerializedBuffer != nullptr) {
        return false;
    }
    unsigned char *buffer = value.GetSerializedBuffer();
    if (buffer == nullptr) {
        return false;
    }
    return PutValue(new Tlv(type, buffer, value.GetSerializedBytes()));
}

bool TlvBox::GetNoValue(int type) const
{
   auto itor = mTlvMap.find(type);
    if (itor != mTlvMap.end()) {
        return true;
    }
    return false;
}

bool TlvBox::GetBoolValue(int type, bool &value) const
{
    auto itor = mTlvMap.find(type);
    if (itor != mTlvMap.end()) {
        value = (*(bool *)(itor->second->GetValue()));
        return true;
    }
    return false;
}

bool TlvBox::GetCharValue(int type, char &value) const
{
    auto itor = mTlvMap.find(type);
    if (itor != mTlvMap.end()) {
        value = (*(char *)(itor->second->GetValue()));
        return true;
    }
    return false;
}

bool TlvBox::GetShortValue(int type, short &value) const
{
    auto itor = mTlvMap.find(type);
    if (itor != mTlvMap.end()) {
        value = ntohs((*(short *)(itor->second->GetValue())));
        return true;
    }
    return false;
}

bool TlvBox::GetIntValue(int type, int &value) const
{
    auto itor = mTlvMap.find(type);
    if (itor != mTlvMap.end()) {
        value = ntohl((*(int *)(itor->second->GetValue())));
        return true;
    }
    return false;
}

bool TlvBox::GetLongValue(int type, long &value) const
{
    auto itor = mTlvMap.find(type);
    if (itor != mTlvMap.end()) {
        value = ntohl((*(long *)(itor->second->GetValue())));
        return true;
    }
    return false;
}

bool TlvBox::GetLongLongValue(int type, long long &value) const
{
    auto itor = mTlvMap.find(type);
    if (itor != mTlvMap.end()) {
        value = ntohll((*(long long *)(itor->second->GetValue())));
        return true;
    }
    return false;
}

bool TlvBox::GetFloatValue(int type, float& value) const
{
    auto itor = mTlvMap.find(type);
    if (itor != mTlvMap.end()) {
        value = swapFloat((*(float *)(itor->second->GetValue())));
        return true;
    }
    return false;
}

bool TlvBox::GetDoubleValue(int type, double& value) const
{
    auto itor = mTlvMap.find(type);
    if (itor != mTlvMap.end()) {
        value = swapDouble((*(double *)(itor->second->GetValue())));
        return true;
    }
    return false;
}

bool TlvBox::GetStringValue(int type, char *value, int &length) const
{
    return GetBytesValue(type,(unsigned char *)value,length);
}

bool TlvBox::GetStringValue(int type, std::string &value) const
{
    auto itor = mTlvMap.find(type);
    if (itor != mTlvMap.end()) {        
        value = (char *)(itor->second->GetValue());        
        return true;
    }
    return false;
}

bool TlvBox::GetBytesValue(int type, unsigned char *value, int &length) const
{
    auto itor = mTlvMap.find(type);
    if (itor == mTlvMap.end()) {
        return false;
    }

    if (length < itor->second->GetLength()) {
        return false;
    }

    memset(value, 0, length);
    length = itor->second->GetLength();
    memcpy(value,itor->second->GetValue(), length);

    return true;
}

bool TlvBox::GetBytesValuePtr(int type, unsigned char **value, int &length) const
{
    auto itor = mTlvMap.find(type);
    if (itor == mTlvMap.end()) {
        return false;        
    }
    *value = itor->second->GetValue();
    length = itor->second->GetLength();    
    return true;
}

bool TlvBox::GetObjectValue(int type, TlvBox& value) const
{
    auto itor = mTlvMap.find(type);
    if (itor == mTlvMap.end()) {
        return false;    
    }
    return value.Parse(itor->second->GetValue(), itor->second->GetLength());
}

int TlvBox::GetTLVList(std::vector<int> &list) const
{
    for (auto iter : mTlvMap) {
        list.push_back(iter.first);
    }
    return list.size();
}

} //namespace 
