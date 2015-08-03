#ifndef __NAT_GET_H__
#define __NAT_GET_H__

#include <boost/noncopyable.hpp>
#include <boost/shared_ptr.hpp>
#include <vector>
#include <string>
#include "type_key.h"
#include <ydx/callback_types.h>
#include <ydx/ydx_mutex.h>
#include <ydx/tcp_server.h>
#include <ydx/epoller.h>
using namespace ydx;

struct nf_info;
struct nfct_handle;
struct nf_conntrack;
struct nfct_filter_dump;
struct request_message;


class NetFilterGet : boost::noncopyable
{
public:
	NetFilterGet();
	~NetFilterGet();
	
	void work(void);
	void Run(request_message* msg, const ydx::TcpConnectionPtr& conn);
	
	int filter_nat(const struct nf_conntrack *obj, 
				const struct nf_conntrack *ct);

	void store_info(char* in_buf);

	void onMessage(const TcpConnectionPtr& conn, ydx::Buffer* buf);
	void onConnection(const TcpConnectionPtr& conn);
	boost::shared_ptr<nf_info> get_info(){return info_;}
	
private:
	int alloc_tmpl_objects(void);
	void free_tmpl_objects(void);
	bool get_key_and_value(std::string & line, 
									std::string & key, 
									std::string & value);		 

	
	boost::shared_ptr<nf_info> info_;
	boost::shared_ptr<nfct_handle> nf_handle_;
	boost::shared_ptr<nfct_filter_dump> filter_dump_;
	

	
	tuple_key_map  netfliter_map_;
	std::vector<std::string> info_buf_;
	int family_;
	mutable ydx::MutexLock mutex_;
	boost::shared_ptr<EPollPoller>  epoller_;
	boost::shared_ptr<TcpServer>    server_;
};


#endif
