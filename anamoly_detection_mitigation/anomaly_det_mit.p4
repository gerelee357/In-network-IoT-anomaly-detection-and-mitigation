/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

// Constants for protocol types
const bit<8>  UDP_PROTOCOL = 0x11;
const bit<16> TYPE_IPV4 = 0x800;
const bit<5>  IPV4_OPTION_MRI = 31;



// Pipeline behavior states
#define NORMAL 0
#define DETECTION 1
#define MITIGATION 2

// Packet classification labels
#define LEGITIMATE 100
#define MALICIOUS  200

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<32> switchID_t;
typedef bit<32> qdepth_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header ipv4_option_t {
    bit<1> copyFlag;
    bit<2> optClass;
    bit<5> option;
    bit<8> optionLength;
}

header mri_t {
    bit<16>  count;
}

header switch_t {
    switchID_t  swid;
    qdepth_t    qdepth;
}

/*the collection of metadata about packets is typically done through pipelines*/
/*Two types of metadata: 1. user-defined metadata
/*2.standard metadata: standard_metadata_t  */

/*user-defined metadata in ingress*/
struct ingress_metadata_t {
    bit<16>  count;
}


/*user-defined metadata in parser*/
struct parser_metadata_t {
    bit<16>  remaining;
}


/* 
Purpose: To maintain the state of the entire pipeline.
Usage: The dr_state field is used to store the current state of the pipeline
(NORMAL, DETECTION, MITIGATION). This state is read from and written 
to a global register, affecting the packet processing logic. 
*/

/*
The whole_pipeline_metadata_t is valid for all stages of the pipeline. It allows for shared state 
information that can be read and written by the parser, ingress, egress, and deparser stages, 
facilitating coordinated and stateful packet processing across the entire P4 program.
This design ensures that decisions made at one stage can influence behavior at subsequent stages, 
enabling complex processing 
logic such as anomaly detection and response mechanisms.
*/


struct whole_pipeline_metadata_t {
    bit<8> dr_state;
}

struct metadata {
    ingress_metadata_t   ingress_metadata;
    parser_metadata_t   parser_metadata;
    whole_pipeline_metadata_t whole_metadata;
    bit<32> meter_tag;
}

struct headers {
    ethernet_t         ethernet;
    ipv4_t             ipv4;
    ipv4_option_t      ipv4_option;
    mri_t              mri;
    switch_t[MAX_HOPS] swtraces;
}


//  behave_states is a global register in the provided P4 program. 
Global registers in P4 store state information that can be accessed and modified by different pipeline stages. 
This allows for stateful processing, where the behavior of the pipeline can change based on the current state stored in the register.*/

register<bit<8>>(1) behave_states;

error { IPHeaderTooShort }

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        verify(hdr.ipv4.ihl >= 5, error.IPHeaderTooShort);
        transition select(hdr.ipv4.ihl) {
            5             : accept;
            default       : parse_ipv4_option;
        }
    }

    state parse_ipv4_option {
        packet.extract(hdr.ipv4_option);
        transition select(hdr.ipv4_option.option)  {
            IPV4_OPTION_MRI: parse_mri;
            default: accept;
        }

    }

    state parse_mri {
        packet.extract(hdr.mri);
        meta.parser_metadata.remaining=hdr.mri.count;

        transition select(meta.parser_metadata.remaining) {
                          0: accept;
                    default: parse_swtrace;
        }


    }

    state parse_swtrace {
        packet.extract(hdr.swtraces.next);
        meta.parser_metadata.remaining = meta.parser_metadata.remaining -1;
        transition select(meta.parser_metadata.remaining) {
                      0     : accept;
                    default : parse_swtrace;

        }

    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

                  counter(512, CounterType.packets_and_bytes) port_counter;


                  action selecting() {
                        behave_states.read(meta.whole_metadata.dr_state,0);
                        // initial value of dr_state is zero
                        //meta.whole_metadata.dr_state = NORMAL;
                  }

                  /*meter declaration*/
                  meter(10, MeterType.packets) my_meter;

                  action m_action(bit<32> meter_index) {   /*packets are tagged.*/
                    my_meter.execute_meter<bit<32>>(meter_index, meta.meter_tag);
                  }

                  action set_tos(bit<8> tos) {
                      hdr.ipv4.diffserv=tos;
                  }

                  action drop() {
                      mark_to_drop(standard_metadata);
                  }

                  table m_read {
                    key = {
                    hdr.ethernet.srcAddr: exact;   /*ethernet address is matched, m_action is invoked and sey a tag*/
                    }
                    actions = {
                    m_action;
                    NoAction;
                    }
                    default_action = NoAction;
                    size = 16384;

                  }

                  table m_filter {
                  key = {
                    meta.meter_tag: exact;
                  }
                  actions = {
                    set_tos;
                    drop;
                    NoAction;
                  }
                  default_action = drop;
                  size = 16;
                  }

                  action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
                      standard_metadata.egress_spec = port;
                      hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
                      hdr.ethernet.dstAddr = dstAddr;
                      hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
                   }



                  table ipv4_lpm {
                      key = {
                          hdr.ipv4.dstAddr: lpm;
                      }
                      actions = {
                          ipv4_forward;
                          drop;
                          NoAction;
                      }
                      size = 1024;
                      default_action = NoAction();
                  }

    apply {

        port_counter.count((bit<32>)standard_metadata.ingress_port);

        selecting();
        meta.whole_metadata.dr_state = NORMAL; 
        behave_states.write(0,meta.whole_metadata.dr_state);

        ipv4_lpm.apply();

        if(meta.whole_metadata.dr_state==MITIGATION) {

           m_read.apply();
           m_filter.apply();

        }
        }

}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {




    counter(512, CounterType.packets_and_bytes) egress_port_counter;

    register<bit<32>>(1) pkt_counter;
    register<bit<32>>(1) sum_of_qdepth;
    bit<32> res;
    bit<32> res1;
    bit<32> mean;


    action anomaly_detection(bit<32> mean_qdepth)
    {
        if(mean_qdepth<40) {
            hdr.swtraces[0].qdepth = LEGITIMATE; // normal data
            meta.whole_metadata.dr_state=NORMAL;
           
            }
        else {
            hdr.swtraces[0].qdepth = MALICIOUS; // attack data
            meta.whole_metadata.dr_state=DETECTION;
            }

    }



    action add_swtrace(switchID_t swid) {

        pkt_counter.read(res, 0);      // Packet Counter
        sum_of_qdepth.read(res1,0);

        res=res+1;
        pkt_counter.write(0, res);

        behave_states.read(meta.whole_metadata.dr_state, 0);

        res1=res1+(qdepth_t)standard_metadata.deq_qdepth;
        sum_of_qdepth.write(0,res1);


        hdr.mri.count = hdr.mri.count +1;
        hdr.swtraces.push_front(1);
        hdr.swtraces[0].setValid();

        hdr.swtraces[0].swid = swid;
        //hdr.swtraces[0].qdepth = (qdepth_t)standard_metadata.deq_qdepth; /*Ug garaltiin portiin queue depth-iig hiij ybuulna*/
        pkt_counter.read(res, 0);
        sum_of_qdepth.read(res1, 0);

        if(swid==1 && res==128 && meta.whole_metadata.dr_state==NORMAL) {
            anomaly_detection(res1>>7);  //No division and modulo operator, so use the right bitshift
            res=0;
            res1=0;
            }

        /*if(swid==1 && meta.whole_metadata.dr_state==NORMAL)
            hdr.swtraces[0].qdepth = (qdepth_t)standard_metadata.deq_qdepth; */

        else if(swid==1 && meta.whole_metadata.dr_state==DETECTION)
            hdr.swtraces[0].qdepth = (qdepth_t)standard_metadata.deq_qdepth;

        else if(swid==1 && meta.whole_metadata.dr_state==MITIGATION)
            hdr.swtraces[0].qdepth = res;


        pkt_counter.write(0, res);      // Reset packet counter(Update register with 0)
        sum_of_qdepth.write(0, res1);

        hdr.ipv4.ihl = hdr.ipv4.ihl + 2;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 8;
        hdr.ipv4_option.optionLength = hdr.ipv4_option.optionLength + 8;

    }


    action add_swtrace1(switchID_t swid) {
          hdr.mri.count = hdr.mri.count + 1;
          hdr.swtraces.push_front(1);
          hdr.swtraces[0].setValid();
          hdr.swtraces[0].swid = swid;
          hdr.swtraces[0].qdepth = (qdepth_t)standard_metadata.deq_qdepth;

          hdr.ipv4.ihl = hdr.ipv4.ihl + 2;
          hdr.ipv4_option.optionLength = hdr.ipv4_option.optionLength + 8;
          hdr.ipv4.totalLen = hdr.ipv4.totalLen + 8;
}


    table swtrace {
        actions        = {
            add_swtrace;
            NoAction;
        }

        default_action =  NoAction();
    }

    apply {
        egress_port_counter.count((bit<32>)standard_metadata.egress_port);


        if(hdr.mri.isValid()) {
        swtrace.apply();
        behave_states.write(0,meta.whole_metadata.dr_state);
        }


    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ipv4_option);
        packet.emit(hdr.mri);
        packet.emit(hdr.swtraces);

        /* TODO: emit ipv4_option, mri and swtraces headers */
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
