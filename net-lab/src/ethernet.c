#include "ethernet.h"

#include "arp.h"
#include "driver.h"
#include "ip.h"
#include "utils.h"
/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 */
void ethernet_in(buf_t *buf) {
    // 如果数据长度小于以太网头部长度，表明数据包不完整，丢弃
    if (buf->len < sizeof(ether_hdr_t)) {
        return; 
    }
    ether_hdr_t *hdr = (ether_hdr_t *)buf->data;  // 解析以太网包头
    uint16_t protocol = swap16(hdr->protocol16);  // 提取协议类型
    buf_remove_header(buf, sizeof(ether_hdr_t));  // 移除以太网包头
    net_in(buf, protocol, hdr->src);              // 向上层传递数据包
}
/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的数据包
 * @param mac 目标MAC地址
 * @param protocol 上层协议
 */
void ethernet_out(buf_t *buf, const uint8_t *mac, net_protocol_t protocol) {
    if (buf->len < ETHERNET_MIN_TRANSPORT_UNIT) {
        buf_add_padding(buf, ETHERNET_MIN_TRANSPORT_UNIT - buf->len);   
    }
    buf_add_header(buf, sizeof(ether_hdr_t));     // 添加以太网包头
    ether_hdr_t *hdr = (ether_hdr_t *)buf->data;  
    memcpy(hdr->dst, mac, NET_MAC_LEN);           // 填写目的MAC地址
    memcpy(hdr->src, net_if_mac, NET_MAC_LEN);    // 填写源MAC地址
    hdr->protocol16 = swap16(protocol);           // 填写协议类型
    driver_send(buf);                             // 发送数据帧
}
/**
 * @brief 初始化以太网协议
 *
 */
void ethernet_init() {
    buf_init(&rxbuf, ETHERNET_MAX_TRANSPORT_UNIT + sizeof(ether_hdr_t));
}

/**
 * @brief 一次以太网轮询
 *
 */
void ethernet_poll() {
    if (driver_recv(&rxbuf) > 0)
        ethernet_in(&rxbuf);
}
