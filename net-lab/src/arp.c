#include "arp.h"

#include "ethernet.h"
#include "net.h"

#include <stdio.h>
#include <string.h>
/**
 * @brief 初始的arp包
 *
 */
static const arp_pkt_t arp_init_pkt = {
    .hw_type16 = swap16(ARP_HW_ETHER),
    .pro_type16 = swap16(NET_PROTOCOL_IP),
    .hw_len = NET_MAC_LEN,
    .pro_len = NET_IP_LEN,
    .sender_ip = NET_IF_IP,
    .sender_mac = NET_IF_MAC,
    .target_mac = {0}};

/**
 * @brief arp地址转换表，<ip,mac>的容器
 *
 */
map_t arp_table;

/**
 * @brief arp buffer，<ip,buf_t>的容器
 *
 */
map_t arp_buf;

/**
 * @brief 打印一条arp表项
 *
 * @param ip 表项的ip地址
 * @param mac 表项的mac地址
 * @param timestamp 表项的更新时间
 */
void arp_entry_print(void *ip, void *mac, time_t *timestamp) {
    printf("%s | %s | %s\n", iptos(ip), mactos(mac), timetos(*timestamp));
}

/**
 * @brief 打印整个arp表
 *
 */
void arp_print() {
    printf("===ARP TABLE BEGIN===\n");
    map_foreach(&arp_table, arp_entry_print);
    printf("===ARP TABLE  END ===\n");
}

/**
 * @brief 发送一个arp请求
 *
 * @param target_ip 想要知道的目标的ip地址
 */
void arp_req(uint8_t *target_ip) {
        
    buf_t txbuf;
    buf_init(&txbuf, sizeof(arp_pkt_t));          // 初始化缓冲区

    // 填写ARP报头
    arp_pkt_t *arp_pkt = (arp_pkt_t *)txbuf.data;
    memcpy(arp_pkt, &arp_init_pkt, sizeof(arp_init_pkt));
    
    memcpy(arp_pkt->target_ip, target_ip, NET_IP_LEN);   // 设置目标IP地址
    arp_pkt->opcode16 = swap16(ARP_REQUEST);    // 设置操作类型为ARP_REQUEST
    
    // 发送ARP报文
    uint8_t broadcast_mac[NET_MAC_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    ethernet_out(&txbuf, broadcast_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 发送一个arp响应
 *
 * @param target_ip 目标ip地址
 * @param target_mac 目标mac地址
 */
void arp_resp(uint8_t *target_ip, uint8_t *target_mac) {
        
    buf_t txbuf;
    buf_init(&txbuf, sizeof(arp_pkt_t));  // 初始化缓冲区
    
    // 填写ARP报头首部
    arp_pkt_t *arp_pkt = (arp_pkt_t *)txbuf.data;
    memcpy(arp_pkt, &arp_init_pkt, sizeof(arp_init_pkt));
    
    // 设置目标MAC地址和IP地址
    memcpy(arp_pkt->target_mac, target_mac, NET_MAC_LEN);
    memcpy(arp_pkt->target_ip, target_ip, NET_IP_LEN);
    
    // 设置操作类型为ARP_REPLY
    arp_pkt->opcode16 = swap16(ARP_REPLY);
    
    // 发送ARP报文
    ethernet_out(&txbuf, target_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void arp_in(buf_t *buf, uint8_t *src_mac) {
    if (buf->len < sizeof(arp_pkt_t)) {
        return;
    }
    arp_pkt_t *arp_pkt = (arp_pkt_t *)buf->data;
    
    // 检查硬件类型、协议类型、地址长度，不合规定就丢弃
    if (swap16(arp_pkt->hw_type16) != ARP_HW_ETHER ||
        swap16(arp_pkt->pro_type16) != NET_PROTOCOL_IP ||
        arp_pkt->hw_len != NET_MAC_LEN ||
        arp_pkt->pro_len != NET_IP_LEN) {
        return; 
    }
    
    uint16_t opcode = swap16(arp_pkt->opcode16);         //检查操作类型
    if (opcode != ARP_REQUEST && opcode != ARP_REPLY) {
        return; 
    }
    map_set(&arp_table, arp_pkt->sender_ip, arp_pkt->sender_mac);       // 更新ARP表项
    buf_t *cached_buf = (buf_t *)map_get(&arp_buf, arp_pkt->sender_ip); // 查看缓存情况

    if (cached_buf != NULL) {    //有缓存就发送缓存的数据包
        ethernet_out(cached_buf, arp_pkt->sender_mac, NET_PROTOCOL_IP);
        map_delete(&arp_buf, arp_pkt->sender_ip);  // 删缓存
    } else {    // 没缓存，检查是否是请求本机MAC的ARP请求
        if (opcode == ARP_REQUEST && 
            memcmp(arp_pkt->target_ip, net_if_ip, NET_IP_LEN) == 0) {
            arp_resp(arp_pkt->sender_ip, arp_pkt->sender_mac);  // 发送ARP响应
        }
    }
}

/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的数据包
 * @param ip 目标ip地址
 */
void arp_out(buf_t *buf, uint8_t *ip) {
    uint8_t *mac = (uint8_t *)map_get(&arp_table, ip);  // 查ARP表
    
    if (mac != NULL) {        //找到对应MAC地址，发送以太网帧
        ethernet_out(buf, mac, NET_PROTOCOL_IP);
    } else {           //没找到，缓存数据包并发送ARP请求
        buf_t *cached_buf = (buf_t *)map_get(&arp_buf, ip);
        if (cached_buf == NULL) {
            map_set(&arp_buf, ip, buf);
            arp_req(ip);
        }
    }
}

/**
 * @brief 初始化arp协议
 *
 */
void arp_init() {
    map_init(&arp_table, NET_IP_LEN, NET_MAC_LEN, 0, ARP_TIMEOUT_SEC, NULL, NULL);
    map_init(&arp_buf, NET_IP_LEN, sizeof(buf_t), 0, ARP_MIN_INTERVAL, NULL, buf_copy);
    net_add_protocol(NET_PROTOCOL_ARP, arp_in);
    arp_req(net_if_ip);
}