#ifndef __TYPE_KEY_H__
#define __TYPE_KEY_H__

#include <unordered_map>
#include <stdint.h>
#include <string.h>
#pragma pack(1)

class tuple_info_key
{
public:
	tuple_info_key() { memset(this, 0, sizeof(*this));}
	bool operator==(const tuple_info_key& sk) const;
	
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t src_port;
	uint16_t dst_port;
};

#pragma pack()

class tuple_hash {
public:
	size_t operator()(const tuple_info_key& sk) const;
};

typedef std::unordered_map<tuple_info_key, uint32_t, tuple_hash> tuple_key_map;
typedef std::unordered_map<tuple_info_key, uint32_t, tuple_hash>::iterator it_tuple_key_map;
#endif