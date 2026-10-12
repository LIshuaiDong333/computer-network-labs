#include "ip.h"

#include "arp.h"
#include "ethernet.h"
#include "icmp.h"
#include "net.h"
#include "utils.h"
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <buf.h>

// static uint16_t ip_id_counter = 0;
/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac) {
    // TO-DO
    if (buf->len < sizeof(ip_hdr_t)) return;

    // 报头检查
    ip_hdr_t *_ip_hdr_t = (ip_hdr_t*)buf->data;
    uint16_t total_len16 = swap16(_ip_hdr_t->total_len16);
    if(_ip_hdr_t->version != IP_VERSION_4) return;
    if(total_len16 > buf->len)  return;

    // 检查校验和
    uint16_t check_sum16_origin = _ip_hdr_t->hdr_checksum16;
    _ip_hdr_t->hdr_checksum16 = 0;
    uint16_t check_sum16_current = checksum16((uint16_t*)_ip_hdr_t, sizeof(ip_hdr_t));
    if(check_sum16_origin != check_sum16_current) return;
    _ip_hdr_t->hdr_checksum16 = check_sum16_current;

    if(memcmp(_ip_hdr_t->dst_ip, net_if_ip, NET_IP_LEN) != 0) return;

    // 去掉填充字段
    if(buf->len > total_len16) buf_remove_padding(buf, buf->len - total_len16);

    // 要去掉报头
    uint8_t protocol = _ip_hdr_t->protocol;
    uint8_t* src     = _ip_hdr_t->src_ip;
    buf_remove_header(buf, sizeof(ip_hdr_t));

    // 向上层传递数据包
    if(net_in(buf, protocol, src) == -1) {
        buf_add_header(buf, sizeof(ip_hdr_t));
        icmp_unreachable(buf, src, ICMP_CODE_PROTOCOL_UNREACH);
    }
}
/**
 * @brief 处理一个要发送的ip分片
 *
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf) {
    // TO-DO
    buf_add_header(buf, sizeof(ip_hdr_t));

    ip_hdr_t* _ip_hdr_t         = (ip_hdr_t*)buf->data;
    _ip_hdr_t->version          = IP_VERSION_4;
    _ip_hdr_t->hdr_len          = sizeof(ip_hdr_t) / 4;
    _ip_hdr_t->tos              = 0;
    _ip_hdr_t->total_len16      = swap16(buf->len);
    _ip_hdr_t->id16             = swap16(id);
    _ip_hdr_t->protocol         = protocol;
    _ip_hdr_t->ttl              = 64;
    _ip_hdr_t->flags_fragment16 = swap16((mf ? IP_MORE_FRAGMENT : 0) | offset);
    _ip_hdr_t->hdr_checksum16   = 0;
    memcpy(_ip_hdr_t->dst_ip, ip, NET_IP_LEN);
    memcpy(_ip_hdr_t->src_ip, net_if_ip, NET_IP_LEN);
 
    uint16_t check_sum16      = checksum16((uint16_t*) _ip_hdr_t, sizeof(ip_hdr_t));
    _ip_hdr_t->hdr_checksum16 = check_sum16;
     
    arp_out(buf, ip);
}

/**
 * @brief 处理一个要发送的ip数据包
 *
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol) {
    // TO-DO
    static int send_id = 0;
    int Max_load_len = ETHERNET_MAX_TRANSPORT_UNIT - sizeof(ip_hdr_t);
    
    if(buf->len <= Max_load_len) {
        ip_fragment_out(buf, ip, protocol, send_id, 0, 0);
    }
    else {
        uint16_t offset = 0;
        buf_t *ip_buf = (buf_t*)malloc(sizeof(buf_t));
        while (buf->len > 0) {
            size_t part_size = (buf->len > Max_load_len) ? Max_load_len : buf->len;
            buf_init(ip_buf, part_size);
            memcpy(ip_buf->data, buf->data, part_size);
            ip_fragment_out(ip_buf, ip, protocol, send_id, offset / IP_HDR_OFFSET_PER_BYTE, (buf->len > Max_load_len) ? 1 : 0);
            
            offset += part_size;
            buf->data += part_size;
            buf->len -= part_size;
        }
    }
    send_id++;
}

/**
 * @brief 初始化ip协议
 *
 */
void ip_init() {
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}