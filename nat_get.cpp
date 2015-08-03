#include <stdio.h>
//#include <getopt.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <arpa/inet.h>
#include <signal.h>
#include <string.h>
#include <netdb.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libmnl/libmnl.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include "nat_get.h"
#include <boost/algorithm/string.hpp>
#include <boost/bind.hpp>
#include <boost/make_shared.hpp>
#include <algorithm>
#include <iostream>
#include <ydx/inet_address.h>





struct u32_mask {
	uint32_t value;
	uint32_t mask;
};

struct request_message
{
	request_message() {memset(this, 0, sizeof(*this));}
	
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t src_port;
	uint16_t dst_port;

};

struct nf_info{
	struct nf_conntrack *ct;
	struct nf_expect *exp;
	/* Expectations require the expectation tuple and the mask. */
	struct nf_conntrack *exptuple, *mask;

	/* Allows filtering/setting specific bits in the ctmark */
	struct u32_mask mark;

	/* Allow to filter by mark from kernel-space. */
	struct nfct_filter_dump_mark filter_mark_kernel;

	/* Allows filtering by ctlabels */
	struct nfct_bitmask *label;
	
	NetFilterGet* net_filter;
};

static int counter;

int dump_cb(enum nf_conntrack_msg_type type,
		   struct nf_conntrack *ct,
		   void *data);




NetFilterGet::NetFilterGet()
	:info_(new nf_info),
	 nf_handle_(nfct_open(CONNTRACK, 0), nfct_close),
	 filter_dump_(nfct_filter_dump_create(), nfct_filter_dump_destroy),
	 family_(AF_INET)
{
	
}

NetFilterGet::~NetFilterGet()
{
	free_tmpl_objects();
}

int NetFilterGet::alloc_tmpl_objects(void)
{
	info_->ct = nfct_new();
	info_->exptuple = nfct_new();
	info_->mask = nfct_new();
	info_->exp = nfexp_new();

	memset(&info_->mark, 0, sizeof(info_->mark));


	

	return info_->ct != NULL && info_->exptuple != NULL &&
	       info_->mask != NULL && info_->exp != NULL;
	
}

void NetFilterGet::work(void)
{
	if (!alloc_tmpl_objects())
	{
		printf("alloc tmpl failed..\n");
		exit(1);
	}
	nfct_callback_register(nf_handle_.get(), NFCT_T_ALL, dump_cb, this);
	info_->net_filter = this;
	InetAddress server_addr("127.0.0.1", 6666);
	
	epoller_ = boost::make_shared<EPollPoller>();
	server_  = boost::make_shared<TcpServer>(epoller_.get(), server_addr, "netfilter");
	server_->setConnectionCallback(boost::bind(&NetFilterGet::onConnection, this, _1));
	server_->setMessageCallback(boost::bind(&NetFilterGet::onMessage, this, _1, _2));	
	server_->start();	
	epoller_->poll();	
}

void NetFilterGet::free_tmpl_objects(void)
{
	if (info_->ct)
		nfct_destroy(info_->ct);
	if (info_->exptuple)
		nfct_destroy(info_->exptuple);
	if (info_->mask)
		nfct_destroy(info_->mask);
	if (info_->exp)
		nfexp_destroy(info_->exp);
	if (info_->label)
		nfct_bitmask_destroy(info_->label);
}

void NetFilterGet::onConnection(const ydx::TcpConnectionPtr& conn)
{
	  std::cout << "EchoServer - " << conn->peerAddress().toIpPort() << " -> "
           << conn->localAddress().toIpPort() << " is "
           << (conn->connected() ? "UP" : "DOWN") << std::endl;
}

void NetFilterGet::onMessage(const ydx::TcpConnectionPtr& conn, ydx::Buffer* buf)
{
	int message_len = 0;
	
	while( buf->readable_bytes() != 0 )
	{
		MutexLockGuard lock(mutex_);
		::memcpy(&message_len, buf->peek(), sizeof(int));
		if((int)(buf->readable_bytes() - sizeof(int)) < message_len)
			break;	
		buf->retrieve(sizeof(int));
		request_message* msg = (request_message*)(buf->peek());
		//做一次nat表查询，将结果通过conn发回给请求端。
		Run(msg, conn);	
		buf->retrieve(sizeof(request_message));
	}
}

void NetFilterGet::Run(request_message* msg, const ydx::TcpConnectionPtr& conn)
{


	netfliter_map_.clear();
	counter = 0;
	
	if(!nf_handle_)
	{
		printf("open nf_handle failed..\n");
		exit(1);
	}
	

	
	
	

	if (filter_dump_ == NULL)
	{
		printf("create filter_dump failed..\n");
		exit(1);
	}

	nfct_filter_dump_set_attr(filter_dump_.get(), NFCT_FILTER_DUMP_MARK,
				  &info_->filter_mark_kernel);
	
	nfct_filter_dump_set_attr_u8(filter_dump_.get(),
				     NFCT_FILTER_DUMP_L3NUM,
				     family_);
	
	nfct_query(nf_handle_.get(), NFCT_Q_DUMP_FILTER_RESET, filter_dump_.get());
	
	


	tuple_info_key key;
	
	key.src_ip = msg->src_ip;
	key.dst_ip = msg->dst_ip;
	key.src_port = msg->src_port;
	key.dst_port = msg->dst_port;
	it_tuple_key_map it;
	if((it = netfliter_map_.find(key)) != netfliter_map_.end())
	{
			conn->send(&it->second, sizeof(uint32_t));
	}
	
	
	printf("total size:%lu\n", netfliter_map_.size());

	printf("total %d lines\n", counter);
	
}


int NetFilterGet::filter_nat(const struct nf_conntrack *obj, const struct nf_conntrack *ct)
{
	int has_srcnat = 1;
	uint32_t ip;
	uint16_t port;
	int check_address = 0, check_port = 0;
	
	if (nfct_attr_is_set(obj, ATTR_SNAT_IPV4)) 
	{
		check_address = 1;
		ip = nfct_get_attr_u32(obj, ATTR_SNAT_IPV4);
		if (nfct_getobjopt(ct, NFCT_GOPT_IS_SNAT) &&
		    ip == nfct_get_attr_u32(ct, ATTR_REPL_IPV4_DST))
			{
				has_srcnat = 0;
			}
			
	}

	if (nfct_attr_is_set(obj, ATTR_SNAT_PORT)) {
		int ret = 0;

		check_port = 1;
		port = nfct_get_attr_u16(obj, ATTR_SNAT_PORT);
		if (nfct_getobjopt(ct, NFCT_GOPT_IS_SPAT) &&
		    port == nfct_get_attr_u16(ct, ATTR_REPL_PORT_DST))
			ret = 1;

		/* the address matches but the port does not. */
		if (check_address && has_srcnat && !ret)
			has_srcnat = 1;
		if (!check_address && ret)
			has_srcnat = 0;
	}

	if (!check_address && !check_port &&
	    (nfct_getobjopt(ct, NFCT_GOPT_IS_SNAT) ||
	     nfct_getobjopt(ct, NFCT_GOPT_IS_SPAT)))
	  	 has_srcnat = 0;	

	return has_srcnat;
	
}

bool NetFilterGet::get_key_and_value(std::string & line, 
					std::string & key, std::string & value)
{
    size_t pos = line.find('=');//找到每行的“=”号位置，之前是key之后是value   
    if(pos==std::string::npos) return false;  
    key = line.substr(0,pos);//取=号之前      
    value = line.substr(pos+1);//取=号之后       
	if(key.length() == 0) return false;
    return true;  
}

void NetFilterGet::store_info(char* in_buf)
{
	if(NULL == in_buf)
		return;

	boost::split(info_buf_, in_buf, boost::is_any_of(" "), boost::token_compress_on); 
/*
	std::for_each(info_buf_.begin(), 
				  info_buf_.end(), 
				 [](std::string x){ printf("%s\n", x.c_str());} );
	printf("size:%lu\n", info_buf_.size());
*/
	if(info_buf_.size() != 15)
		return;
	
	tuple_info_key tuple_key;
	std::vector<std::string> inner_buf;
	
	in_addr addr;
	std::string key, value;
	//reply src ip
	if(!get_key_and_value(info_buf_[8], key, value))
		return;
	::inet_pton(AF_INET, value.c_str(), &addr);
	tuple_key.src_ip = ::ntohl(addr.s_addr);
	//开始填写key字段
	//reply dst ip
	if(!get_key_and_value(info_buf_[9], key, value))
		return;
	::inet_pton(AF_INET, value.c_str(), &addr);
	tuple_key.dst_ip = ::ntohl(addr.s_addr);
	//reply src port
	if(!get_key_and_value(info_buf_[10], key, value))
		return;	
	tuple_key.src_port = atol(value.c_str());
	//reply src port
	if(!get_key_and_value(info_buf_[11], key, value))
		return;		
	tuple_key.dst_port = atol(value.c_str());
	////////////解析值/////////////////
	uint32_t ip = 0;
	if(!get_key_and_value(info_buf_[4], key, value))
		return;
	::inet_pton(AF_INET, value.c_str(), &addr);
	ip = ::ntohl(addr.s_addr);


	if(netfliter_map_.find(tuple_key) == netfliter_map_.end())
	{
		
		netfliter_map_.insert(std::pair<tuple_info_key, uint32_t>(tuple_key, ip));
	}

	
	
}

int dump_cb(enum nf_conntrack_msg_type type,
		   struct nf_conntrack *ct,
		   void *data)
{
	NetFilterGet* nef = reinterpret_cast<NetFilterGet*>(data);

	boost::shared_ptr<nf_info> ptr = nef->get_info();
	struct nf_conntrack *obj = ptr->ct;
	
	char buf[1024];
	unsigned int op_type = NFCT_O_DEFAULT;
	unsigned int op_flags = 0;
	if (nef->filter_nat(obj, ct))
		return NFCT_CB_CONTINUE;
	
	nfct_snprintf_labels(buf, sizeof(buf), ct, NFCT_T_UNKNOWN, op_type, op_flags, NULL);
	nef->store_info(buf);
	
	printf("%s\n", buf);


	counter++;
	

	return NFCT_CB_CONTINUE;
}
