
#include <core.p4>
#include <v1model.p4>


#define CPU_CLONE_SESSION_ID 99



typedef bit<9>   port_num_t;
typedef bit<48>  mac_addr_t;
typedef bit<16>  mcast_group_id_t;
typedef bit<32>  ipv4_addr_t;
typedef bit<128> ipv6_addr_t;
typedef bit<16>  l4_port_t;






header ethernet_t {
    mac_addr_t  dst_addr;
    mac_addr_t  src_addr;
    bit<16>     ether_type;
}

header ipv6_t {
    bit<4>   version;
    bit<8>   traffic_class;
    bit<20>  flow_label;
    bit<16>  payload_len;
    bit<8>   next_hdr;
    bit<8>   hop_limit;
    bit<128> src_addr;
    bit<128> dst_addr;
}

header tcp_t {
    bit<16>  src_port;
    bit<16>  dst_port;
    bit<32>  seq_no;
    bit<32>  ack_no;
    bit<4>   data_offset;
    bit<3>   res;
    bit<3>   ecn;
    bit<6>   ctrl;
    bit<16>  window;
    bit<16>  checksum;
    bit<16>  urgent_ptr;
}

header udp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> len;
    bit<16> checksum;
}

header icmp_t {
    bit<8>   type;
    bit<8>   icmp_code;
    bit<16>  checksum;
    bit<16>  identifier;
    bit<16>  sequence_number;
    bit<64>  timestamp;
}

header icmpv6_t {
    bit<8>   type;
    bit<8>   code;
    bit<16>  checksum;
}

header ndp_t {
    bit<32>      flags;
    ipv6_addr_t  target_ipv6_addr;

    bit<8>       type;
    bit<8>       length;
    bit<48>      target_mac_addr;
}


@controller_header("packet_in")
header packet_in_t {
    port_num_t  ingress_port;
    bit<7>      _pad;
}


@controller_header("packet_out")
header packet_out_t {
    port_num_t  egress_port;
    bit<7>      _pad;
}


struct parsed_headers_t {
    packet_out_t  packet_out;
    packet_in_t   packet_in;
    ethernet_t    ethernet;
    ipv6_t        ipv6;
    tcp_t         tcp;
    udp_t         udp;
    icmpv6_t      icmpv6;
    ndp_t         ndp;
}



struct local_metadata_t {
    l4_port_t  l4_src_port;
    l4_port_t  l4_dst_port;
    bool       is_multicast;
}





parser ParserImpl (packet_in packet,
                   out parsed_headers_t hdr,
                   inout local_metadata_t local_metadata,
                   inout standard_metadata_t standard_metadata)
{
   
    state start {
        transition select(standard_metadata.ingress_port) {
            CPU_PORT: parse_packet_out;
            default: parse_ethernet;
        }
    }

    state parse_packet_out {
        packet.extract(hdr.packet_out);
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type){
            ETHERTYPE_IPV6: parse_ipv6;
            default: accept;
        }
    }

    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        transition select(hdr.ipv6.next_hdr) {
            IP_PROTO_TCP:    parse_tcp;
            IP_PROTO_UDP:    parse_udp;
            IP_PROTO_ICMPV6: parse_icmpv6;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
       
        local_metadata.l4_src_port = hdr.tcp.src_port;
        local_metadata.l4_dst_port = hdr.tcp.dst_port;
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        
        local_metadata.l4_src_port = hdr.udp.src_port;
        local_metadata.l4_dst_port = hdr.udp.dst_port;
        transition accept;
    }

    state parse_icmpv6 {
        packet.extract(hdr.icmpv6);
        transition select(hdr.icmpv6.type) {
            ICMP6_TYPE_NS: parse_ndp;
            ICMP6_TYPE_NA: parse_ndp;
            default: accept;
        }
    }

    state parse_ndp {
        packet.extract(hdr.ndp);
        transition accept;
    }
}




control IngressPipeImpl (inout parsed_headers_t    hdr,
                         inout local_metadata_t    local_metadata,
                         inout standard_metadata_t standard_metadata) {

    
    action drop() {
        
        mark_to_drop(standard_metadata);
    }

    

    

    table my_station_table {
        key = {
            hdr.ethernet.dst_addr: exact;
        }
        actions = { NoAction; }
        @name("my_station_table_counter")
        counters = direct_counter(CounterType.packets_and_bytes);
    }

    
    action_selector(HashAlgorithm.crc16, 32w1024, 32w16) ecmp_selector;

    action set_next_hop(mac_addr_t dmac) {
        hdr.ethernet.src_addr = hdr.ethernet.dst_addr;
        hdr.ethernet.dst_addr = dmac;
       
        hdr.ipv6.hop_limit = hdr.ipv6.hop_limit - 1;
    }

    
    table routing_v6_table {
      key = {
          hdr.ipv6.dst_addr:          lpm;
          
          hdr.ipv6.dst_addr:          selector;
          hdr.ipv6.src_addr:          selector;
          hdr.ipv6.flow_label:        selector;
          hdr.ipv6.next_hdr:          selector;
          local_metadata.l4_src_port: selector;
          local_metadata.l4_dst_port: selector;
      }
      actions = {
          set_next_hop;
      }
      implementation = ecmp_selector;
      @name("routing_v6_table_counter")
      counters = direct_counter(CounterType.packets_and_bytes);
    }

   

    

    action ndp_ns_to_na(mac_addr_t target_mac) {
        hdr.ethernet.src_addr = target_mac;
        hdr.ethernet.dst_addr = IPV6_MCAST_01;
        ipv6_addr_t host_ipv6_tmp = hdr.ipv6.src_addr;
        hdr.ipv6.src_addr = hdr.ndp.target_ipv6_addr;
        hdr.ipv6.dst_addr = host_ipv6_tmp;
        hdr.ipv6.next_hdr = IP_PROTO_ICMPV6;
        hdr.icmpv6.type = ICMP6_TYPE_NA;
        hdr.ndp.flags = NDP_FLAG_ROUTER | NDP_FLAG_OVERRIDE;
        hdr.ndp.type = NDP_OPT_TARGET_LL_ADDR;
        hdr.ndp.length = 1;
        hdr.ndp.target_mac_addr = target_mac;
        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    
    apply {

        
        if (hdr.packet_out.isValid()) {
            
            standard_metadata.egress_spec = hdr.packet_out.egress_port;
           
            hdr.packet_out.setInvalid();
            
            exit;
        }

        bool do_l3_l2 = true;

        
        
        if (hdr.icmpv6.isValid() && hdr.icmpv6.type == ICMP6_TYPE_NS) {
            if (ndp_reply_table.apply().hit) {
                do_l3_l2 = false;
            }
        }
        

       

        if (do_l3_l2) {

            
            if (hdr.ipv6.isValid() && my_station_table.apply().hit) {
                routing_v6_table.apply();
                
                if(hdr.ipv6.hop_limit == 0) { drop(); }
            }

            
            if (!l2_exact_table.apply().hit) {
                
                l2_ternary_table.apply();
            }
        }

        
        acl_table.apply();
    }
}



control EgressPipeImpl (inout parsed_headers_t hdr,
                        inout local_metadata_t local_metadata,
                        inout standard_metadata_t standard_metadata) {
    apply {
        
        if (standard_metadata.egress_port == CPU_PORT) {
            
            hdr.packet_in.setValid();
            hdr.packet_in.ingress_port = standard_metadata.ingress_port;
            // Exit the pipeline here.
            exit;
        }

        
        if (local_metadata.is_multicast == true &&
              standard_metadata.ingress_port == standard_metadata.egress_port) {
            mark_to_drop(standard_metadata);
        }
    }
}


control ComputeChecksumImpl(inout parsed_headers_t hdr,
                            inout local_metadata_t local_metadata)
{
    apply {
        
        update_checksum(hdr.ndp.isValid(),
            {
                hdr.ipv6.src_addr,
                hdr.ipv6.dst_addr,
                hdr.ipv6.payload_len,
                8w0,
                hdr.ipv6.next_hdr,
                hdr.icmpv6.type,
                hdr.icmpv6.code,
                hdr.ndp.flags,
                hdr.ndp.target_ipv6_addr,
                hdr.ndp.type,
                hdr.ndp.length,
                hdr.ndp.target_mac_addr
            },
            hdr.icmpv6.checksum,
            HashAlgorithm.csum16
        );
    }
}



control DeparserImpl(packet_out packet, in parsed_headers_t hdr) {
    apply {
        packet.emit(hdr.packet_in);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv6);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.icmpv6);
        packet.emit(hdr.ndp);
    }
}


V1Switch(
    ParserImpl(),
    VerifyChecksumImpl(),
    IngressPipeImpl(),
    EgressPipeImpl(),
    ComputeChecksumImpl(),
    DeparserImpl()
) main;
