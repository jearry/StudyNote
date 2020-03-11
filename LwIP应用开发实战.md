# LwIP应用开发实战

## 1、网络协议简介

略

## 2、LwIP简介

- 全名：Light wight IP
- 作者：瑞典计算机科学院

- 最新版本：2.1.2
- 设计初衷：用少量资源消耗实现一个较为完整的TCP/IP协议栈
- 开源且商用友好
- 国内大部分物联网OS，都基于LwIP
- 官方文档：http://www.nongnu.org/lwip/2_1_x/index.html
- 支持以下协议：
  - ARP
  - ICMP
  - IGMP
  - UDP
  - TCP
  - PPP
  - DNS
  - DHCP
  - IPv4、IPv6
  - SNMP
  - AUTOIP（自动IP地址配置）
- 文件介绍
  - api：netconn和socket API相关
  - apps：应用程序
  - core：内核
  - include：头文件
  - netif：网卡移植