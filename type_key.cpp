#include "type_key.h"
#include "MurmurHash2.h"



bool tuple_info_key::operator==(const tuple_info_key& sk) const 
{
	return (src_ip == sk.src_ip) && (dst_ip == sk.dst_ip)
		    && (src_port == sk.src_port) && (dst_port == sk.dst_port);
}


size_t tuple_hash::operator()(const tuple_info_key& sk) const
{
	return MurmurHash64A(&sk, sizeof(sk), 0xee6b27eb);
}