# LwIP应用开发实战

## 1、网络协议简介

### 1）TCP/IP的封包和解包

![image-20200312140213295](images\LwIP\tcpip报文处理.png)

## 2、LwIP简介

### 1）简介

- 全名：Light wight IP

- 作者：瑞典计算机科学院

- 最新版本：2.1.2

- 设计初衷：用少量资源消耗实现一个较为完整的TCP/IP协议栈

- 开源且商用友好

- 国内大部分物联网OS，都基于LwIP

- 官方文档：http://www.nongnu.org/lwip/2_1_x/index.html

### 2）支持的协议

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

### 3） 文件介绍
  - api：netconn和socket API相关
  - apps：应用程序
  - core：内核
  - include：头文件
  - netif：网卡移植

### 4） VS code
  - Shift+Ctrl+O：查看符号列表
  - F12，Alt+F12：跳转定义
  - Alt + <- ->：跳回

### 5） 三种编程接口
  - RAW/Callback API
    - 效率高
    - 实时性低
    - 复杂，不容易使用
    - 有可能丢包
  - NETCONN API
    - 基于OS IPC
    - 对网络连接抽象成文件
    - 封包、拆包用独立线程tcpip_thread，优先级很高
    - 数据处理无copy，netbuf、pbuf
    - 容易使用
    - 效率较低
    - 实时性高
  - SOCKET API
    - 基于NETCONN API
    - 更易于使用
    - 效率更低
    - 数据处理存在copy

## 3、开发平台介绍

### 1) 以太网介绍
  - 标准
    - IEEE 802.3：以太网
    - IEEE 802.11：无线局域网
    - IEEE 802.15：个人局域网，蓝牙
      - IEEE 802.15.4：ZigBee
    
  - PHY层
    - 物理层规定了传输介质、传输速度、数据编码方式和冲突检测机制
    - 一般是一个PHY芯片实现其功能，比如LAN8720A
    - 10BASE-T
      - 速率10Mbps
      - 编码：曼彻斯特（无需外部时钟，高转低为1，低转高为0，效率低只有50%）
    - 100BASE-T
      - 速率100Mbps
      - 编码：4B/5B（4位数据用5位编码表示，有足够多的的跳变，能同步，效率高达到80%）
    - CSMA/CD冲突检测
      - 多个节点接到同一个总线，接收数据和原始发送比较，存在冲突则随机等待一段时间重发
      - 目前都是星型连接，不会产生冲突
    
- MAC层

  - 主要负责与物理层进行数据交接

  - 对上层的数据，增加MAC层的控制信号，交给物理层

  - 对物理层收到的数据，去掉MAC层的控制信号，交给上层

  - MAC包数据格式

    ![image-20200311102640169](images\LwIP\MAC数据包格式.png)

    - 前导字段：7个0x55，MAC层会过滤掉
    - 帧起始界定符：0xD5，MAC层会过滤掉
    - 类型/长度：大于0x600为类型
    - 数据：0-1500长度
    - 填充：MAC数据包最低长度为64字节，"数据"长度少于46字节时，自动填充无效数据
    - FCS：CRC校验

### 2) STM32的ETH外设

  ![image-20200311104723985](images\LwIP\ETH功能图.png)

- MII接口

  - 用于理解MAC控制器和PHY芯片，提供数据传输路径
  - 需要16根通信线

- RMII接口

  - 简化版本的MII，功能相同
  - 只需要7根通信线
  - LAN8720A只支持该接口

- PHY硬件设计

  ![image-20200311105418659](images\LwIP\PHY硬件设计.png)

## 4、LwIP的网络接口管理

### 1） netif介绍
- netif 是 LwIP 抽象出来的网卡，屏蔽硬件接口的差异
  - 为一个列表
  - 不同的网卡修改 ethernetif.c 文件即可
  - netif结构体
```C++
struct netif {
#if !LWIP_SINGLE_NETIF
  /** pointer to next in linked list */
  struct netif *next;
#endif

#if LWIP_IPV4
  /** IP address configuration in network byte order */
  ip_addr_t ip_addr;
  ip_addr_t netmask;
  ip_addr_t gw;
#endif /* LWIP_IPV4 */
  /** This function is called by the network device driver
   *  to pass a packet up the TCP/IP stack. */
  netif_input_fn input;
#if LWIP_IPV4
  /** This function is called by the IP module when it wants
   *  to send a packet on the interface. This function typically
   *  first resolves the hardware address, then sends the packet.
   *  For ethernet physical layer, this is usually etharp_output() */
  netif_output_fn output;
#endif /* LWIP_IPV4 */
  /** This function is called by ethernet_output() when it wants
   *  to send a packet on the interface. This function outputs
   *  the pbuf as-is on the link medium. */
  netif_linkoutput_fn linkoutput;
#if LWIP_NETIF_STATUS_CALLBACK
  /** This function is called when the netif state is set to up or down
   */
  netif_status_callback_fn status_callback;
#endif /* LWIP_NETIF_STATUS_CALLBACK */
#if LWIP_NETIF_LINK_CALLBACK
  /** This function is called when the netif link is set to up or down
   */
  netif_status_callback_fn link_callback;
#endif /* LWIP_NETIF_LINK_CALLBACK */
#if LWIP_NETIF_REMOVE_CALLBACK
  /** This function is called when the netif has been removed */
  netif_status_callback_fn remove_callback;
#endif /* LWIP_NETIF_REMOVE_CALLBACK */
  /** This field can be set by the device driver and could point
   *  to state information for the device. */
  void *state;
#ifdef netif_get_client_data
  void* client_data[LWIP_NETIF_CLIENT_DATA_INDEX_MAX + LWIP_NUM_NETIF_CLIENT_DATA];
#endif
#if LWIP_NETIF_HOSTNAME
  /* the hostname for this netif, NULL is a valid value */
  const char*  hostname;
#endif /* LWIP_NETIF_HOSTNAME */
#if LWIP_CHECKSUM_CTRL_PER_NETIF
  u16_t chksum_flags;
#endif /* LWIP_CHECKSUM_CTRL_PER_NETIF*/
  /** maximum transfer unit (in bytes) */
  u16_t mtu;
  /** link level hardware address of this interface */
  u8_t hwaddr[NETIF_MAX_HWADDR_LEN];
  /** number of bytes used in hwaddr */
  u8_t hwaddr_len;
  /** flags (@see @ref netif_flags) */
  u8_t flags;
  /** descriptive abbreviation */
  char name[2];
  /** number of this interface. Used for @ref if_api and @ref netifapi_netif, 
   * as well as for IPv6 zones */
  u8_t num;
#if MIB2_STATS
  /** link type (from "snmp_ifType" enum from snmp_mib2.h) */
  u8_t link_type;
  /** (estimate) link speed */
  u32_t link_speed;
  /** timestamp at last change made (up/down) */
  u32_t ts;
  /** counters */
  struct stats_mib2_netif_ctrs mib2_counters;
#endif /* MIB2_STATS */
#if LWIP_IPV4 && LWIP_IGMP
  /** This function could be called to add or delete an entry in the multicast
      filter table of the ethernet MAC.*/
  netif_igmp_mac_filter_fn igmp_mac_filter;
#endif /* LWIP_IPV4 && LWIP_IGMP */
#if LWIP_NETIF_USE_HINTS
  struct netif_hint *hints;
#endif /* LWIP_NETIF_USE_HINTS */
#if ENABLE_LOOPBACK
  /* List of packets to be queued for ourselves. */
  struct pbuf *loop_first;
  struct pbuf *loop_last;
#if LWIP_LOOPBACK_MAX_PBUFS
  u16_t loop_cnt_current;
#endif /* LWIP_LOOPBACK_MAX_PBUFS */
#endif /* ENABLE_LOOPBACK */
};
```
### 2） netif使用
- 挂载

  - 通过netif_add()函数将我们的网卡挂载到 netif_list 链表上

- 与netif相关的底层函数

  - low_level_init：网卡初始化，设置网卡MAC地址，长度，最大发送单元等

    ```C++
    static void low_level_init(struct netif *netif);
    ```

  - low_level_output：网卡发送函数
	```C++
    static err_t low_level_output(struct netif *netif, struct pbuf *p);
  ```

  - low_level_input：网卡接收函数

    ```C++
    static struct pbuf * low_level_input(struct netif *netif);
    ```

- 另外两个与网卡相关的函数

  - ethernetif_init：初始化回调，单网卡无需修改

    ```C++
    err_t ethernetif_init(struct netif *netif);
    ```

  - ethernetif_input：收包处理，同时上报给内核

    ```C++
    void ethernetif_input(struct netif *netif)
    {
      struct pbuf *p;
    
      /* move received packet into a new pbuf */
      p = low_level_input(netif);
      /* if no packet could be read, silently ignore this */
      if (p != NULL) {
        /* pass all packets to ethernet_input, which decides what packets it supports */
        if (netif->input(p, netif) != ERR_OK) {
          pbuf_free(p);
          p = NULL;
        }
      }
    }
    ```

## 5、LwIP的内存管理

	系统每次调用LIBC的内存管理函数的执行时间可能都不一样，在嵌入式环境下这个是致命缺陷

### 1） 动态内存池

  - memp_std.h实现介绍

    - 定义
    ![](images\LwIP\memp_std定义.png)
      
    - 使用

      ```C++
      typedef enum
      {
          #define LWIP_MEMPOOL(name,num,size,desc) MEMP_##name,
          #include "lwip/priv/memp_std.h"
          MEMP_MAX
      } memp_t;
      ```

    - 结果

      ```C++
      typedef enum
      {
          MEMP_RAW_PCB,
      	MEMP_UDP_PCB,
      	MEMP_TCP_PCB,
      	MEMP_TCP_PCB_LISTEN,
      	MEMP_TCP_SEG,
      	MEMP_ALTCP_PCB,
      	MEMP_REASSDATA,
      	MEMP_NETBUF,
      	MEMP_NETCONN,
      	MEMP_MAX
      } memp_t;
      ```

  - 初始化

    ```C++
    void memp_init(void)
    ```

  - 分配，内有同步机制多线程安全

    ```C++
    void * memp_malloc(memp_t type)
    ```

  - 释放，内有同步机制多线程安全

    ```C++
    void memp_free(memp_t type, void *mem)
    ```

### 2） 动态内存堆

  - 初始化

    ```C++
    void mem_init(void)
    ```

  - 分配，内有同步机制多线程安全

    ```C++
    void * mem_malloc(mem_size_t size_in)
    ```

  - 释放，内有同步机制多线程安全，同时会进行附近的内存块合并操作

    ```C++
    void mem_free(void *rmem)
    ```

### 3） 内存相关配置

  - MEM_LIBC_MALLOC
    - 是否使用 C 标准库自带的内存分配策略
    - 默认情况下为 0，表示不使用
  - MEMP_MEM_MALLOC
    - 是否使用 LwIP 内存堆分配策略实现内存池分配
    - 默认情况下为 0，标识不使用
    - 与MEM_USE_POOLS 只能二选一
  - MEM_USE_POOLS
    - 是否使用 LwIP 内存池分配策略实现内存堆的分配
    - 默认情况下为0，表示不使用
    - 与MEMP_MEM_MALLOC 只能二选一

## 6、网络数据包

### 1）分层思想
- TCP/IP协议分层思想

  - 各层都是独立的模块，有清晰的层次结构，不会越界去读写数据
  - 数据需要层层拷贝，效率低

- LwIP模糊分层概念

  - 采用内存共享机制，避免数据拷贝，效率高
  - 处理数据需要更小心谨慎，容易出错

### 2）pbuf结构体说明

  ![image-20200312102241886](images\LwIP\pbuf结构体.png)

### 3）pbuf类型

  - PBUF_RAM：从内存堆分配而来

    ![image-20200312102938358](images\LwIP\pbuf_ram.png)

  - PBUF_POOL：从内存池分配而来

    - 和PBUF_RAM类似

  - PBUF_ROM

    - 从内存池分配而来
    - 不包含数据区域
    - pbuf数据存储在ROM中

    ![image-20200311162437035](images\LwIP\pbuf_rom.png)

  - PBUF_REF

    - 从内存池分配而来
    - 不包含数据区域
    - pbuf数据存储在RAM中

  - 各种类型可以组合成一个链表

![image-20200311162608513](images\LwIP\pbuf_comb.png)

### 4）pbuf使用
- pbuf_alloc，分配

  ```C++
  struct pbuf * pbuf_alloc(pbuf_layer layer, u16_t length, pbuf_type type);
  ```

  - layer：为各层预留的内存大小

    ```C++
    #define PBUF_TRANSPORT_HLEN 20
    #define PBUF_IP_HLEN        20
    #define PBUF_LINK_ENCAPSULATION_HLEN 0
    #define ETH_PAD_SIZE                    2
    #define PBUF_LINK_HLEN                  (14 + ETH_PAD_SIZE)
    
    typedef enum {
      PBUF_TRANSPORT = PBUF_LINK_ENCAPSULATION_HLEN + PBUF_LINK_HLEN + PBUF_IP_HLEN + BUF_TRANSPORT_HLEN,
      PBUF_IP = PBUF_LINK_ENCAPSULATION_HLEN + PBUF_LINK_HLEN + PBUF_IP_HLEN,
      PBUF_LINK = PBUF_LINK_ENCAPSULATION_HLEN + PBUF_LINK_HLEN,
      PBUF_RAW_TX = PBUF_LINK_ENCAPSULATION_HLEN,
      PBUF_RAW = 0
    } pbuf_layer;
    ```

- pbuf_free，释放

  ```C++
  u8_t pbuf_free(struct pbuf *p)
  ```

- pbuf_realloc，在尾部释放一定空间

  ```C++
  void pbuf_realloc(struct pbuf *p, u16_t new_len)
  ```

- pbuf_header，调整pbuf的payload指针（-header_size_increment，增加头），len和tot_len都会随之更新

  ```C++
  u8_t pbuf_header(struct pbuf *p, s16_t header_size_increment)
  ```

- pbuf_remove_header，调整pbuf的payload指针（+header_size_decrement，去掉头），len和tot_len都会随之更新

  ```C++
  u8_t pbuf_remove_header(struct pbuf *p, size_t header_size_decrement)
  ```

  pbuf_take，向pbuf的payload复制数据

  ```C++
  err_t pbuf_take(struct pbuf *buf, const void *dataptr, u16_t len)
  ```

- pbuf_copy，pbuf之间复制

  ```C++
  err_t pbuf_copy(struct pbuf *p_to, const struct pbuf *p_from)
  ```

- pbuf_chain，链接两个pbuf为一个链表

  ```C++
  void pbuf_chain(struct pbuf *h, struct pbuf *t)
  ```

- pbuf_ref，pbuf引用计数加1

  ```C++
  void pbuf_ref(struct pbuf *p)
  ```

## 7、无操作系统移植LwIP

### 1）将LwIP添加到工程

### 2）修改配置

- lwipopts.h，LwIP的参数配置

  - NO_SYS：1
  - LWIP_NETCONN：0
  - LWIP_SOCKET：0

- cc.h，处理器相关配置

- pref.h，统计和测量相关

  ```C++
  //无需测量定义为空即可
  #define PERF_START /* null definition */
  #define PERF_STOP(x) /* null definition */
  ```

### 3）移植网卡驱动

- ethernetif.c

### 4）LwIP时基

- 实现sys_now函数获取系统时钟

  ```C++
  u32_t sys_now(void)
  {
  	return HAL_GetTick();
  }
  ```

### 5）协议栈初始化

```c++
#define IP_ADDR3 122

/*NETMASK*/
#define NETMASK_ADDR0 255
#define NETMASK_ADDR1 255
#define NETMASK_ADDR2 255
#define NETMASK_ADDR3 0

/*Gateway Address*/
#define GW_ADDR0 192
#define GW_ADDR1 168
#define GW_ADDR2 1
#define GW_ADDR3 1
/* USER CODE END 0 */

void LwIP_Init(void)
{
	IP4_ADDR(&ipaddr,IP_ADDR0,IP_ADDR1,IP_ADDR2,IP_ADDR3);
	IP4_ADDR(&netmask,NETMASK_ADDR0,NETMASK_ADDR1,
	NETMASK_ADDR2,NETMASK_ADDR3);
	IP4_ADDR(&gw,GW_ADDR0,GW_ADDR1,GW_ADDR2,GW_ADDR3);

	/* Initilialize the LwIP stack without RTOS */
	lwip_init();

	/* add the network interface (IPv4/IPv6) without RTOS */
	netif_add(&gnetif, &ipaddr, &netmask, &gw, NULL,
	&ethernetif_init, &ethernet_input);

	/* Registers the default network interface */
	netif_set_default(&gnetif);

	if (netif_is_link_up(&gnetif))
	{
		/*When the netif is fully configured this function must be called */
		netif_set_up(&gnetif);
	}
	else
	{
		/* When the netif link is down this function must be called */
		netif_set_down(&gnetif);
	}
}
```

### 6）获取数据包

```C++
int main(void)
{
	//板级外设初始化
	BSP_Init();
	//LwIP 协议栈初始化
	LwIP_Init();

	while (1)
	{
		//调用网卡接收函数
		ethernetif_input(&gnetif);
		//处理 LwIP 中定时事件
		sys_check_timeouts();
	}
}
```

### 7）验证测试

`ping 192.168.1.122`

## 8、有操作系统移植LwIP

### 1）将OS源码和LwIP添加到工程

### 2）修改配置

- lwipopts.h，LwIP的参数配置
  - NO_SYS：0
  - LWIP_NETCONN：1
  - LWIP_SOCKET：1

### 3）适配OS

- sys_arch.c、sys_arch.h

### 4）移植网卡驱动

- ethernetif.c

### 5）协议栈初始化

- 增加tpcip_thread线程创建处理

### 6）获取数据包

参见第9章

### 7）验证测试

`ping 192.168.1.122`

## 9、LwIP一探究竟

### 1）网卡接收数据流程

![image-20200312092515372](images\LwIP\网卡接收数据流程.png)

### 2）tcpip_thread线程

![image-20200312092620881](images\LwIP\tcpip_thread.png)

### 3）LwIP中的消息

- tcpip_msg结构

  ```c++
  enum tcpip_msg_type {
  #if !LWIP_TCPIP_CORE_LOCKING
    TCPIP_MSG_API,
    TCPIP_MSG_API_CALL,
  #endif /* !LWIP_TCPIP_CORE_LOCKING */
  #if !LWIP_TCPIP_CORE_LOCKING_INPUT
    TCPIP_MSG_INPKT,
  #endif /* !LWIP_TCPIP_CORE_LOCKING_INPUT */
  #if LWIP_TCPIP_TIMEOUT && LWIP_TIMERS
    TCPIP_MSG_TIMEOUT,
    TCPIP_MSG_UNTIMEOUT,
  #endif /* LWIP_TCPIP_TIMEOUT && LWIP_TIMERS */
    TCPIP_MSG_CALLBACK,
    TCPIP_MSG_CALLBACK_STATIC
  };
  
  struct tcpip_msg {
    enum tcpip_msg_type type;
    union {
  #if !LWIP_TCPIP_CORE_LOCKING
      struct {
        tcpip_callback_fn function;
        void* msg;
      } api_msg;
      struct {
        tcpip_api_call_fn function;
        struct tcpip_api_call_data *arg;
        sys_sem_t *sem;
      } api_call;
  #endif /* LWIP_TCPIP_CORE_LOCKING */
  #if !LWIP_TCPIP_CORE_LOCKING_INPUT
      struct {
        struct pbuf *p;
        struct netif *netif;
        netif_input_fn input_fn;
      } inp;
  #endif /* !LWIP_TCPIP_CORE_LOCKING_INPUT */
      struct {
        tcpip_callback_fn function;
        void *ctx;
      } cb;
  #if LWIP_TCPIP_TIMEOUT && LWIP_TIMERS
      struct {
        u32_t msecs;
        sys_timeout_handler h;
        void *arg;
      } tmo;
  #endif /* LWIP_TCPIP_TIMEOUT && LWIP_TIMERS */
    } msg;
  };
  ```

- 数据包消息

![image-20200312091837088](images\LwIP\数据包消息运作.png)

- API消息

![image-20200312091912464](images\LwIP\api消息运作.png)

## 10、ARP协议

### 1）简介
- MAC地址

  - 长度：6个字节
  - 单播地址bit0为0
  - 多播地址bit0为1
  - 广播地址为全1

- 网卡数据处理

  - 无回复机制
  - 收到数据包，如果地址不匹配，或CRC校验不对，网卡只是丢弃

- ARP缓存

  - 一般过期时间为10分钟

### 2）LwIP缓存表

- 缓存表定义

  ```C++
  #define ARP_TABLE_SIZE                  10
  
  /** ARP states */
  enum etharp_state {
    ETHARP_STATE_EMPTY = 0,
    ETHARP_STATE_PENDING,
    ETHARP_STATE_STABLE,
    ETHARP_STATE_STABLE_REREQUESTING_1,
    ETHARP_STATE_STABLE_REREQUESTING_2
  #if ETHARP_SUPPORT_STATIC_ENTRIES
    , ETHARP_STATE_STATIC
  #endif /* ETHARP_SUPPORT_STATIC_ENTRIES */
  };
  
  struct etharp_entry {
  #if ARP_QUEUEING
    /** Pointer to queue of pending outgoing packets on this ARP entry. */
    struct etharp_q_entry *q;
  #else /* ARP_QUEUEING */
    /** Pointer to a single pending outgoing packet on this ARP entry. */
    struct pbuf *q;
  #endif /* ARP_QUEUEING */
    ip4_addr_t ipaddr;
    struct netif *netif;
    struct eth_addr ethaddr;
    u16_t ctime;
    u8_t state;
  };
  
  static struct etharp_entry arp_table[ARP_TABLE_SIZE];
  ```

### 3）运作机制

  - A发数据给B
  - A首先检查自己的ARP缓存表，查看是否有B的IP地址和MAC地址的记录
  - 如果没有，则广播ARP请求
  - 收到ARP请求的主机检查自己的IP和请求的IP相同，相同则回应，不相同丢弃
  - A收到回应后更新B的IP地址和MAC对应关系

### 4）ARP报文结构

  ![image-20200312162807915](images\LwIP\ARP报文.png)

  ```C++
PACK_STRUCT_BEGIN
/** the ARP message, see RFC 826 ("Packet format") */
struct etharp_hdr {
  PACK_STRUCT_FIELD(u16_t hwtype);
  PACK_STRUCT_FIELD(u16_t proto);
  PACK_STRUCT_FLD_8(u8_t  hwlen);
  PACK_STRUCT_FLD_8(u8_t  protolen);
  PACK_STRUCT_FIELD(u16_t opcode);
  PACK_STRUCT_FLD_S(struct eth_addr shwaddr);
  PACK_STRUCT_FLD_S(struct ip4_addr_wordaligned sipaddr);
  PACK_STRUCT_FLD_S(struct eth_addr dhwaddr);
  PACK_STRUCT_FLD_S(struct ip4_addr_wordaligned dipaddr);
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END
  ```



### 5）发送

  ```C++
err_t etharp_request(struct netif *netif, const ip4_addr_t *ipaddr)
{
  return etharp_request_dst(netif, ipaddr, &ethbroadcast);
}

err_t etharp_request_dst(struct netif *netif, const ip4_addr_t *ipaddr, const struct eth_addr *hw_dst_addr)
{
  return etharp_raw(netif, (struct eth_addr *)netif->hwaddr, hw_dst_addr,
                    (struct eth_addr *)netif->hwaddr, netif_ip4_addr(netif), &ethzero,
                    ipaddr, ARP_REQUEST);
}

err_t etharp_raw(struct netif *netif, const struct eth_addr *ethsrc_addr,
           const struct eth_addr *ethdst_addr,
           const struct eth_addr *hwsrc_addr, const ip4_addr_t *ipsrc_addr,
           const struct eth_addr *hwdst_addr, const ip4_addr_t *ipdst_addr,
           const u16_t opcode)
{
  struct pbuf *p;
  err_t result = ERR_OK;
  struct etharp_hdr *hdr;

  /* allocate a pbuf for the outgoing ARP request packet */
  p = pbuf_alloc(PBUF_LINK, SIZEOF_ETHARP_HDR, PBUF_RAM);
  /* could allocate a pbuf for an ARP request? */
  if (p == NULL) {
    ETHARP_STATS_INC(etharp.memerr);
    return ERR_MEM;
  }

  hdr = (struct etharp_hdr *)p->payload;
  hdr->opcode = lwip_htons(opcode);


  /* Write the ARP MAC-Addresses */
  SMEMCPY(&hdr->shwaddr, hwsrc_addr, ETH_HWADDR_LEN);
  SMEMCPY(&hdr->dhwaddr, hwdst_addr, ETH_HWADDR_LEN);
  /* Copy struct ip4_addr_wordaligned to aligned ip4_addr, to support compilers without
   * structure packing. */
  IPADDR_WORDALIGNED_COPY_FROM_IP4_ADDR_T(&hdr->sipaddr, ipsrc_addr);
  IPADDR_WORDALIGNED_COPY_FROM_IP4_ADDR_T(&hdr->dipaddr, ipdst_addr);

  hdr->hwtype = PP_HTONS(LWIP_IANA_HWTYPE_ETHERNET);
  hdr->proto = PP_HTONS(ETHTYPE_IP);
  /* set hwlen and protolen */
  hdr->hwlen = ETH_HWADDR_LEN;
  hdr->protolen = sizeof(ip4_addr_t);

  /* send ARP query */
#if LWIP_AUTOIP
  /* If we are using Link-Local, all ARP packets that contain a Link-Local
   * 'sender IP address' MUST be sent using link-layer broadcast instead of
   * link-layer unicast. (See RFC3927 Section 2.5, last paragraph) */
  if (ip4_addr_islinklocal(ipsrc_addr)) {
    ethernet_output(netif, p, ethsrc_addr, &ethbroadcast, ETHTYPE_ARP);
  } else
#endif /* LWIP_AUTOIP */
  {
    ethernet_output(netif, p, ethsrc_addr, ethdst_addr, ETHTYPE_ARP);
  }

  ETHARP_STATS_INC(etharp.xmit);
  /* free ARP query packet */
  pbuf_free(p);
  p = NULL;
  /* could not allocate pbuf for ARP request */

  return result;
}

err_t ethernet_output(struct netif * netif, struct pbuf * p,
                      const struct eth_addr * src, const struct eth_addr * dst,
                      u16_t eth_type) {
    struct eth_hdr *ethhdr;
    u16_t eth_type_be = lwip_htons(eth_type);

    {
        if (pbuf_add_header(p, SIZEOF_ETH_HDR) != 0) {
            goto pbuf_header_failed;
        }
    }

    ethhdr = (struct eth_hdr *)p->payload;
    ethhdr->type = eth_type_be;
    SMEMCPY(&ethhdr->dest, dst, ETH_HWADDR_LEN);
    SMEMCPY(&ethhdr->src,  src, ETH_HWADDR_LEN);

    
    /* send the packet */
    return netif->linkoutput(netif, p);

    pbuf_header_failed:
    LINK_STATS_INC(link.lenerr);
    return ERR_BUF;
}
  ```

### 6）接收

  ```C++
//有删减
err_t ethernet_input(struct pbuf *p, struct netif *netif)
{
    struct eth_hdr *ethhdr;
    u16_t type;
    #if LWIP_ARP || ETHARP_SUPPORT_VLAN || LWIP_IPV6
    u16_t next_hdr_offset = SIZEOF_ETH_HDR;
    #endif /* LWIP_ARP || ETHARP_SUPPORT_VLAN */

    //略...

    if (ethhdr->dest.addr[0] & 1) {
        /* this might be a multicast or broadcast packet */
        if (ethhdr->dest.addr[0] == LL_IP4_MULTICAST_ADDR_0) {
            #if LWIP_IPV4
            if ((ethhdr->dest.addr[1] == LL_IP4_MULTICAST_ADDR_1) &&
                (ethhdr->dest.addr[2] == LL_IP4_MULTICAST_ADDR_2)) {
                /* mark the pbuf as link-layer multicast */
                p->flags |= PBUF_FLAG_LLMCAST;
            }
            #endif /* LWIP_IPV4 */
        }
        else if (eth_addr_cmp(&ethhdr->dest, &ethbroadcast)) {
            /* mark the pbuf as link-layer broadcast */
            p->flags |= PBUF_FLAG_LLBCAST;
        }
    }

    switch (type) {
            #if LWIP_IPV4 && LWIP_ARP
            /* IP packet? */
        case PP_HTONS(ETHTYPE_IP):
            if (!(netif->flags & NETIF_FLAG_ETHARP)) {
                goto free_and_return;
            }
            /* skip Ethernet header (min. size checked above) */
            if (pbuf_remove_header(p, next_hdr_offset)) {
                goto free_and_return;
            } else {
                /* pass to IP layer */
                ip4_input(p, netif);
            }
            break;

        case PP_HTONS(ETHTYPE_ARP):
            if (!(netif->flags & NETIF_FLAG_ETHARP)) {
                goto free_and_return;
            }
            /* skip Ethernet header (min. size checked above) */
            if (pbuf_remove_header(p, next_hdr_offset)) {
                ETHARP_STATS_INC(etharp.lenerr);
                ETHARP_STATS_INC(etharp.drop);
                goto free_and_return;
            } else {
                /* pass p to ARP module */
                etharp_input(p, netif);
            }
            break;
            #endif /* LWIP_IPV4 && LWIP_ARP */

            //略...
    }

    /* This means the pbuf is freed or consumed,
       so the caller doesn't have to free it again */
    return ERR_OK;

    free_and_return:
    pbuf_free(p);
    return ERR_OK;
}
  ```

  ## 11、IP协议

### 1）简介

- IP地址

![image-20200313104554067](images\LwIP\IP地址.png)

### 2）IP报文结构

![image-20200313105047058](D:\Book\StudyNote\images\LwIP\IP数据报-封装.png)

![image-20200313104813552](images\LwIP\IP数据报.png)

```C++
PACK_STRUCT_BEGIN
/* The IPv4 header */
struct ip_hdr {
  /* version / header length */
  PACK_STRUCT_FLD_8(u8_t _v_hl);
  /* type of service */
  PACK_STRUCT_FLD_8(u8_t _tos);
  /* total length */
  PACK_STRUCT_FIELD(u16_t _len);
  /* identification */
  PACK_STRUCT_FIELD(u16_t _id);
  /* fragment offset field */
  PACK_STRUCT_FIELD(u16_t _offset);
#define IP_RF 0x8000U        /* reserved fragment flag */
#define IP_DF 0x4000U        /* don't fragment flag */
#define IP_MF 0x2000U        /* more fragments flag */
#define IP_OFFMASK 0x1fffU   /* mask for fragmenting bits */
  /* time to live */
  PACK_STRUCT_FLD_8(u8_t _ttl);
  /* protocol*/
  PACK_STRUCT_FLD_8(u8_t _proto);
  /* checksum */
  PACK_STRUCT_FIELD(u16_t _chksum);
  /* source and destination IP addresses */
  PACK_STRUCT_FLD_S(ip4_addr_p_t src);
  PACK_STRUCT_FLD_S(ip4_addr_p_t dest);
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END    
```

### 3）PCB

```C++
#define IP_PCB                             \
  /* ip addresses in network byte order */ \
  ip_addr_t local_ip;                      \
  ip_addr_t remote_ip;                     \
  /* Bound netif index */                  \
  u8_t netif_idx;                          \
  /* Socket options */                     \
  u8_t so_options;                         \
  /* Type Of Service */                    \
  u8_t tos;                                \
  /* Time To Live */                       \
  u8_t ttl                                 \
  /* link layer address resolution hint */ \
  IP_PCB_NETIFHINT
      
struct ip_pcb {
  /* Common members of all PCB types */
  IP_PCB;
};
```

### 4）IP数据包分片

- 链路层协议的 MTU 严格地限制着 IP 数据报的长度。  
- 发送主机分片，路由器只是转发，目标接收端负责组装
- 最后一片的标志字段最后一位为0，其他片为1

![image-20200313110718861](images\LwIP\IP分片示意图.png)

### 5）发送

```C++
err_t ip4_output(struct pbuf *p, const ip4_addr_t *src, const ip4_addr_t *dest,
           u8_t ttl, u8_t tos, u8_t proto)
{
  struct netif *netif;

  LWIP_IP_CHECK_PBUF_REF_COUNT_FOR_TX(p);

  if ((netif = ip4_route_src(src, dest)) == NULL) {
    IP_STATS_INC(ip.rterr);
    return ERR_RTE;
  }

  return ip4_output_if(p, src, dest, ttl, tos, proto, netif);
}



/**
 * Same as ip_output_if() but 'src' address is not replaced by netif address
 * when it is 'any'.
 */
err_t ip4_output_if_src(struct pbuf *p, const ip4_addr_t *src, const ip4_addr_t *dest,
                  u8_t ttl, u8_t tos,
                  u8_t proto, struct netif *netif)
{
#if IP_OPTIONS_SEND
  return ip4_output_if_opt_src(p, src, dest, ttl, tos, proto, netif, NULL, 0);
}

/**
 * Same as ip_output_if_opt() but 'src' address is not replaced by netif address
 * when it is 'any'.
 */
err_t ip4_output_if_opt_src(struct pbuf *p, const ip4_addr_t *src, const ip4_addr_t *dest,
                      u8_t ttl, u8_t tos, u8_t proto, struct netif *netif, void *ip_options,
                      u16_t optlen)
{
#endif /* IP_OPTIONS_SEND */
  struct ip_hdr *iphdr;
  ip4_addr_t dest_addr;
#if CHECKSUM_GEN_IP_INLINE
  u32_t chk_sum = 0;
#endif /* CHECKSUM_GEN_IP_INLINE */

  LWIP_IP_CHECK_PBUF_REF_COUNT_FOR_TX(p);

  MIB2_STATS_INC(mib2.ipoutrequests);

  /* Should the IP header be generated or is it already included in p? */
  if (dest != LWIP_IP_HDRINCL) {
    u16_t ip_hlen = IP_HLEN;
#if IP_OPTIONS_SEND
    u16_t optlen_aligned = 0;
    if (optlen != 0) {
#if CHECKSUM_GEN_IP_INLINE
      int i;
#endif /* CHECKSUM_GEN_IP_INLINE */
      if (optlen > (IP_HLEN_MAX - IP_HLEN)) {
        /* optlen too long */
        IP_STATS_INC(ip.err);
        MIB2_STATS_INC(mib2.ipoutdiscards);
        return ERR_VAL;
      }
      /* round up to a multiple of 4 */
      optlen_aligned = (u16_t)((optlen + 3) & ~3);
      ip_hlen = (u16_t)(ip_hlen + optlen_aligned);
      /* First write in the IP options */
      if (pbuf_add_header(p, optlen_aligned)) {
        IP_STATS_INC(ip.err);
        MIB2_STATS_INC(mib2.ipoutdiscards);
        return ERR_BUF;
      }
      MEMCPY(p->payload, ip_options, optlen);
      if (optlen < optlen_aligned) {
        /* zero the remaining bytes */
        memset(((char *)p->payload) + optlen, 0, (size_t)(optlen_aligned - optlen));
      }
#if CHECKSUM_GEN_IP_INLINE
      for (i = 0; i < optlen_aligned / 2; i++) {
        chk_sum += ((u16_t *)p->payload)[i];
      }
#endif /* CHECKSUM_GEN_IP_INLINE */
    }
#endif /* IP_OPTIONS_SEND */
    /* generate IP header */
    if (pbuf_add_header(p, IP_HLEN)) {
      
      IP_STATS_INC(ip.err);
      MIB2_STATS_INC(mib2.ipoutdiscards);
      return ERR_BUF;
    }

    iphdr = (struct ip_hdr *)p->payload;
    
    IPH_TTL_SET(iphdr, ttl);
    IPH_PROTO_SET(iphdr, proto);
#if CHECKSUM_GEN_IP_INLINE
    chk_sum += PP_NTOHS(proto | (ttl << 8));
#endif /* CHECKSUM_GEN_IP_INLINE */

    /* dest cannot be NULL here */
    ip4_addr_copy(iphdr->dest, *dest);
#if CHECKSUM_GEN_IP_INLINE
    chk_sum += ip4_addr_get_u32(&iphdr->dest) & 0xFFFF;
    chk_sum += ip4_addr_get_u32(&iphdr->dest) >> 16;
#endif /* CHECKSUM_GEN_IP_INLINE */

    IPH_VHL_SET(iphdr, 4, ip_hlen / 4);
    IPH_TOS_SET(iphdr, tos);
#if CHECKSUM_GEN_IP_INLINE
    chk_sum += PP_NTOHS(tos | (iphdr->_v_hl << 8));
#endif /* CHECKSUM_GEN_IP_INLINE */
    IPH_LEN_SET(iphdr, lwip_htons(p->tot_len));
#if CHECKSUM_GEN_IP_INLINE
    chk_sum += iphdr->_len;
#endif /* CHECKSUM_GEN_IP_INLINE */
    IPH_OFFSET_SET(iphdr, 0);
    IPH_ID_SET(iphdr, lwip_htons(ip_id));
#if CHECKSUM_GEN_IP_INLINE
    chk_sum += iphdr->_id;
#endif /* CHECKSUM_GEN_IP_INLINE */
    ++ip_id;

    if (src == NULL) {
      ip4_addr_copy(iphdr->src, *IP4_ADDR_ANY4);
    } else {
      /* src cannot be NULL here */
      ip4_addr_copy(iphdr->src, *src);
    }

#if CHECKSUM_GEN_IP_INLINE
    chk_sum += ip4_addr_get_u32(&iphdr->src) & 0xFFFF;
    chk_sum += ip4_addr_get_u32(&iphdr->src) >> 16;
    chk_sum = (chk_sum >> 16) + (chk_sum & 0xFFFF);
    chk_sum = (chk_sum >> 16) + chk_sum;
    chk_sum = ~chk_sum;
    IF__NETIF_CHECKSUM_ENABLED(netif, NETIF_CHECKSUM_GEN_IP) {
      iphdr->_chksum = (u16_t)chk_sum; /* network order */
    }
#if LWIP_CHECKSUM_CTRL_PER_NETIF
    else {
      IPH_CHKSUM_SET(iphdr, 0);
    }
#endif /* LWIP_CHECKSUM_CTRL_PER_NETIF*/
#else /* CHECKSUM_GEN_IP_INLINE */
    IPH_CHKSUM_SET(iphdr, 0);
#if CHECKSUM_GEN_IP
    IF__NETIF_CHECKSUM_ENABLED(netif, NETIF_CHECKSUM_GEN_IP) {
      IPH_CHKSUM_SET(iphdr, inet_chksum(iphdr, ip_hlen));
    }
#endif /* CHECKSUM_GEN_IP */
#endif /* CHECKSUM_GEN_IP_INLINE */
  } else {
    /* IP header already included in p */
    if (p->len < IP_HLEN) {
      IP_STATS_INC(ip.err);
      MIB2_STATS_INC(mib2.ipoutdiscards);
      return ERR_BUF;
    }
    iphdr = (struct ip_hdr *)p->payload;
    ip4_addr_copy(dest_addr, iphdr->dest);
    dest = &dest_addr;
  }

  IP_STATS_INC(ip.xmit);

  ip4_debug_print(p);

#if ENABLE_LOOPBACK
  if (ip4_addr_cmp(dest, netif_ip4_addr(netif))
#if !LWIP_HAVE_LOOPIF
      || ip4_addr_isloopback(dest)
#endif /* !LWIP_HAVE_LOOPIF */
     ) {
    /* Packet to self, enqueue it for loopback */
    return netif_loop_output(netif, p);
  }
#if LWIP_MULTICAST_TX_OPTIONS
  if ((p->flags & PBUF_FLAG_MCASTLOOP) != 0) {
    netif_loop_output(netif, p);
  }
#endif /* LWIP_MULTICAST_TX_OPTIONS */
#endif /* ENABLE_LOOPBACK */
#if IP_FRAG
  /* don't fragment if interface has mtu set to 0 [loopif] */
  if (netif->mtu && (p->tot_len > netif->mtu)) {
    return ip4_frag(p, netif, dest);
  }
#endif /* IP_FRAG */

  return netif->output(netif, p, dest);
}
```

### 6）接收

```C++
err_t
ip4_input(struct pbuf *p, struct netif *inp)
{
  const struct ip_hdr *iphdr;
  struct netif *netif;
  u16_t iphdr_hlen;
  u16_t iphdr_len;
#if IP_ACCEPT_LINK_LAYER_ADDRESSING || LWIP_IGMP
  int check_ip_src = 1;
#endif /* IP_ACCEPT_LINK_LAYER_ADDRESSING || LWIP_IGMP */
#if LWIP_RAW
  raw_input_state_t raw_status;
#endif /* LWIP_RAW */

  IP_STATS_INC(ip.recv);
  MIB2_STATS_INC(mib2.ipinreceives);

  /* identify the IP header */
  iphdr = (struct ip_hdr *)p->payload;
  if (IPH_V(iphdr) != 4) {
    ip4_debug_print(p);
    pbuf_free(p);
    IP_STATS_INC(ip.err);
    IP_STATS_INC(ip.drop);
    MIB2_STATS_INC(mib2.ipinhdrerrors);
    return ERR_OK;
  }

#ifdef LWIP_HOOK_IP4_INPUT
  if (LWIP_HOOK_IP4_INPUT(p, inp)) {
    /* the packet has been eaten */
    return ERR_OK;
  }
#endif

  /* obtain IP header length in bytes */
  iphdr_hlen = IPH_HL_BYTES(iphdr);
  /* obtain ip length in bytes */
  iphdr_len = lwip_ntohs(IPH_LEN(iphdr));

  /* Trim pbuf. This is especially required for packets < 60 bytes. */
  if (iphdr_len < p->tot_len) {
    pbuf_realloc(p, iphdr_len);
  }

  /* header length exceeds first pbuf length, or ip length exceeds total pbuf length? */
  if ((iphdr_hlen > p->len) || (iphdr_len > p->tot_len) || (iphdr_hlen < IP_HLEN)) {
    /* free (drop) packet pbufs */
    pbuf_free(p);
    IP_STATS_INC(ip.lenerr);
    IP_STATS_INC(ip.drop);
    MIB2_STATS_INC(mib2.ipindiscards);
    return ERR_OK;
  }

  /* verify checksum */
#if CHECKSUM_CHECK_IP
  IF__NETIF_CHECKSUM_ENABLED(inp, NETIF_CHECKSUM_CHECK_IP) {
    if (inet_chksum(iphdr, iphdr_hlen) != 0) {

      ip4_debug_print(p);
      pbuf_free(p);
      IP_STATS_INC(ip.chkerr);
      IP_STATS_INC(ip.drop);
      MIB2_STATS_INC(mib2.ipinhdrerrors);
      return ERR_OK;
    }
  }
#endif

  /* copy IP addresses to aligned ip_addr_t */
  ip_addr_copy_from_ip4(ip_data.current_iphdr_dest, iphdr->dest);
  ip_addr_copy_from_ip4(ip_data.current_iphdr_src, iphdr->src);

  /* match packet against an interface, i.e. is this packet for us? */
  if (ip4_addr_ismulticast(ip4_current_dest_addr())) {
#if LWIP_IGMP
    if ((inp->flags & NETIF_FLAG_IGMP) && (igmp_lookfor_group(inp, ip4_current_dest_addr()))) {
      /* IGMP snooping switches need 0.0.0.0 to be allowed as source address (RFC 4541) */
      ip4_addr_t allsystems;
      IP4_ADDR(&allsystems, 224, 0, 0, 1);
      if (ip4_addr_cmp(ip4_current_dest_addr(), &allsystems) &&
          ip4_addr_isany(ip4_current_src_addr())) {
        check_ip_src = 0;
      }
      netif = inp;
    } else {
      netif = NULL;
    }
#else /* LWIP_IGMP */
    if ((netif_is_up(inp)) && (!ip4_addr_isany_val(*netif_ip4_addr(inp)))) {
      netif = inp;
    } else {
      netif = NULL;
    }
#endif /* LWIP_IGMP */
  } else {
    /* start trying with inp. if that's not acceptable, start walking the
       list of configured netifs. */
    if (ip4_input_accept(inp)) {
      netif = inp;
    } else {
      netif = NULL;
#if !LWIP_NETIF_LOOPBACK || LWIP_HAVE_LOOPIF
      /* Packets sent to the loopback address must not be accepted on an
       * interface that does not have the loopback address assigned to it,
       * unless a non-loopback interface is used for loopback traffic. */
      if (!ip4_addr_isloopback(ip4_current_dest_addr()))
#endif /* !LWIP_NETIF_LOOPBACK || LWIP_HAVE_LOOPIF */
      {
#if !LWIP_SINGLE_NETIF
        NETIF_FOREACH(netif) {
          if (netif == inp) {
            /* we checked that before already */
            continue;
          }
          if (ip4_input_accept(netif)) {
            break;
          }
        }
#endif /* !LWIP_SINGLE_NETIF */
      }
    }
  }

#if IP_ACCEPT_LINK_LAYER_ADDRESSING
  /* Pass DHCP messages regardless of destination address. DHCP traffic is addressed
   * using link layer addressing (such as Ethernet MAC) so we must not filter on IP.
   * According to RFC 1542 section 3.1.1, referred by RFC 2131).
   *
   * If you want to accept private broadcast communication while a netif is down,
   * define LWIP_IP_ACCEPT_UDP_PORT(dst_port), e.g.:
   *
   * #define LWIP_IP_ACCEPT_UDP_PORT(dst_port) ((dst_port) == PP_NTOHS(12345))
   */
  if (netif == NULL) {
    /* remote port is DHCP server? */
    if (IPH_PROTO(iphdr) == IP_PROTO_UDP) {
      const struct udp_hdr *udphdr = (const struct udp_hdr *)((const u8_t *)iphdr + iphdr_hlen);
      
      if (IP_ACCEPT_LINK_LAYER_ADDRESSED_PORT(udphdr->dest)) {
        netif = inp;
        check_ip_src = 0;
      }
    }
  }
#endif /* IP_ACCEPT_LINK_LAYER_ADDRESSING */

  /* broadcast or multicast packet source address? Compliant with RFC 1122: 3.2.1.3 */
#if LWIP_IGMP || IP_ACCEPT_LINK_LAYER_ADDRESSING
  if (check_ip_src
#if IP_ACCEPT_LINK_LAYER_ADDRESSING
      /* DHCP servers need 0.0.0.0 to be allowed as source address (RFC 1.1.2.2: 3.2.1.3/a) */
      && !ip4_addr_isany_val(*ip4_current_src_addr())
#endif /* IP_ACCEPT_LINK_LAYER_ADDRESSING */
     )
#endif /* LWIP_IGMP || IP_ACCEPT_LINK_LAYER_ADDRESSING */
  {
    if ((ip4_addr_isbroadcast(ip4_current_src_addr(), inp)) ||
        (ip4_addr_ismulticast(ip4_current_src_addr()))) {
      /* packet source is not valid */
      /* free (drop) packet pbufs */
      pbuf_free(p);
      IP_STATS_INC(ip.drop);
      MIB2_STATS_INC(mib2.ipinaddrerrors);
      MIB2_STATS_INC(mib2.ipindiscards);
      return ERR_OK;
    }
  }

  /* packet not for us? */
  if (netif == NULL) {
    /* packet not for us, route or discard */
    
#if IP_FORWARD
    /* non-broadcast packet? */
    if (!ip4_addr_isbroadcast(ip4_current_dest_addr(), inp)) {
      /* try to forward IP packet on (other) interfaces */
      ip4_forward(p, (struct ip_hdr *)p->payload, inp);
    } else
#endif /* IP_FORWARD */
    {
      IP_STATS_INC(ip.drop);
      MIB2_STATS_INC(mib2.ipinaddrerrors);
      MIB2_STATS_INC(mib2.ipindiscards);
    }
    pbuf_free(p);
    return ERR_OK;
  }
  /* packet consists of multiple fragments? */
  if ((IPH_OFFSET(iphdr) & PP_HTONS(IP_OFFMASK | IP_MF)) != 0) {
#if IP_REASSEMBLY /* packet fragment reassembly code present? */
    /* reassemble the packet*/
    p = ip4_reass(p);
    /* packet not fully reassembled yet? */
    if (p == NULL) {
      return ERR_OK;
    }
    iphdr = (const struct ip_hdr *)p->payload;
#else /* IP_REASSEMBLY == 0, no packet fragment reassembly code present */
    pbuf_free(p);
    IP_STATS_INC(ip.opterr);
    IP_STATS_INC(ip.drop);
    /* unsupported protocol feature */
    MIB2_STATS_INC(mib2.ipinunknownprotos);
    return ERR_OK;
#endif /* IP_REASSEMBLY */
  }

#if IP_OPTIONS_ALLOWED == 0 /* no support for IP options in the IP header? */

#if LWIP_IGMP
  /* there is an extra "router alert" option in IGMP messages which we allow for but do not police */
  if ((iphdr_hlen > IP_HLEN) &&  (IPH_PROTO(iphdr) != IP_PROTO_IGMP)) {
#else
  if (iphdr_hlen > IP_HLEN) {
#endif /* LWIP_IGMP */
    pbuf_free(p);
    IP_STATS_INC(ip.opterr);
    IP_STATS_INC(ip.drop);
    /* unsupported protocol feature */
    MIB2_STATS_INC(mib2.ipinunknownprotos);
    return ERR_OK;
  }
#endif /* IP_OPTIONS_ALLOWED == 0 */

  /* send to upper layers */
  ip4_debug_print(p);
  
  ip_data.current_netif = netif;
  ip_data.current_input_netif = inp;
  ip_data.current_ip4_header = iphdr;
  ip_data.current_ip_header_tot_len = IPH_HL_BYTES(iphdr);

#if LWIP_RAW
  /* raw input did not eat the packet? */
  raw_status = raw_input(p, inp);
  if (raw_status != RAW_INPUT_EATEN)
#endif /* LWIP_RAW */
  {
    pbuf_remove_header(p, iphdr_hlen); /* Move to payload, no check necessary. */

    switch (IPH_PROTO(iphdr)) {
#if LWIP_UDP
      case IP_PROTO_UDP:
#if LWIP_UDPLITE
      case IP_PROTO_UDPLITE:
#endif /* LWIP_UDPLITE */
        MIB2_STATS_INC(mib2.ipindelivers);
        udp_input(p, inp);
        break;
#endif /* LWIP_UDP */
#if LWIP_TCP
      case IP_PROTO_TCP:
        MIB2_STATS_INC(mib2.ipindelivers);
        tcp_input(p, inp);
        break;
#endif /* LWIP_TCP */
#if LWIP_ICMP
      case IP_PROTO_ICMP:
        MIB2_STATS_INC(mib2.ipindelivers);
        icmp_input(p, inp);
        break;
#endif /* LWIP_ICMP */
#if LWIP_IGMP
      case IP_PROTO_IGMP:
        igmp_input(p, inp, ip4_current_dest_addr());
        break;
#endif /* LWIP_IGMP */
      default:
#if LWIP_RAW
        if (raw_status == RAW_INPUT_DELIVERED) {
          MIB2_STATS_INC(mib2.ipindelivers);
        } else
#endif /* LWIP_RAW */
        {
#if LWIP_ICMP
          /* send ICMP destination protocol unreachable unless is was a broadcast */
          if (!ip4_addr_isbroadcast(ip4_current_dest_addr(), netif) &&
              !ip4_addr_ismulticast(ip4_current_dest_addr())) {
            pbuf_header_force(p, (s16_t)iphdr_hlen); /* Move to ip header, no check necessary. */
            icmp_dest_unreach(p, ICMP_DUR_PROTO);
          }
#endif /* LWIP_ICMP */

          
          IP_STATS_INC(ip.proterr);
          IP_STATS_INC(ip.drop);
          MIB2_STATS_INC(mib2.ipinunknownprotos);
        }
        pbuf_free(p);
        break;
    }
  }

  /* @todo: this is not really necessary... */
  ip_data.current_netif = NULL;
  ip_data.current_input_netif = NULL;
  ip_data.current_ip4_header = NULL;
  ip_data.current_ip_header_tot_len = 0;
  ip4_addr_set_any(ip4_current_src_addr());
  ip4_addr_set_any(ip4_current_dest_addr());

  return ERR_OK;
}
```

## 12、网际控制报文协议ICMP

### 1）简介

- 为什么需要 ICMP？
  -  IP 协议认为丢掉没用的数据是合理的，这样子能提高数据处理的效率
  - 但是源主机更希望能得到当数据没能发送到目标的时候有个回应，不然目标主机都不知道发的数据到了哪里，到达接收没有，就像石沉大海一样，这是不可接受的
  - ICMP 也被主机和路由器用来彼此沟通网络层的信息
- ICMP基于IP

### 2）ICMP报文结构

![image-20200313120228726](images\LwIP\ICMP报文封装.png)

![image-20200313133824498](images\LwIP\ICMP报文结构.png)

```C++
PACK_STRUCT_BEGIN
struct icmp_echo_hdr {
  PACK_STRUCT_FLD_8(u8_t type);
  PACK_STRUCT_FLD_8(u8_t code);
  PACK_STRUCT_FIELD(u16_t chksum);
  PACK_STRUCT_FIELD(u16_t id);
  PACK_STRUCT_FIELD(u16_t seqno);
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END
```

### 3）ICMP报文类型

- 差错报文
  - 目的不可达：3
    - 路由器收到一个无法传递下去的IP数据报，丢弃的同时返回
  - 源站抑制：4
    - 拥塞控制用，告诉源主机不要发这么多数据报
  - 重定向：5
    - 路由器发现可以转发给其他路由器时，告诉主机对路由表做相应改动
    - 提高数据传输效率
  - 超时：11
    - 数据报TTL为0时，路由器会丢弃，同时返回
  - 参数错误：12
    - 首部出现错误时，路由器丢弃并返回
- 查询报文
  - 回显：0、8
    - ping基于ICMP
    - 内核处理
  - 路由器询问：9、10
  - 时间戳：13、14
  - 信息请求：15、16
  - 掩码：17、18

### 4）发送

```C++
void
icmp_dest_unreach(struct pbuf *p, enum icmp_dur_type t)
{
  MIB2_STATS_INC(mib2.icmpoutdestunreachs);
  icmp_send_response(p, ICMP_DUR, t);
}

#if IP_FORWARD || IP_REASSEMBLY
/**
 * Send a 'time exceeded' packet, called from ip_forward() if TTL is 0.
 *
 * @param p the input packet for which the 'time exceeded' should be sent,
 *          p->payload pointing to the IP header
 * @param t type of the 'time exceeded' packet
 */
void
icmp_time_exceeded(struct pbuf *p, enum icmp_te_type t)
{
  MIB2_STATS_INC(mib2.icmpouttimeexcds);
  icmp_send_response(p, ICMP_TE, t);
}

#endif /* IP_FORWARD || IP_REASSEMBLY */

/**
 * Send an icmp packet in response to an incoming packet.
 *
 * @param p the input packet for which the 'unreachable' should be sent,
 *          p->payload pointing to the IP header
 * @param type Type of the ICMP header
 * @param code Code of the ICMP header
 */
static void
icmp_send_response(struct pbuf *p, u8_t type, u8_t code)
{
  struct pbuf *q;
  struct ip_hdr *iphdr;
  /* we can use the echo header here */
  struct icmp_echo_hdr *icmphdr;
  ip4_addr_t iphdr_src;
  struct netif *netif;

  /* increase number of messages attempted to send */
  MIB2_STATS_INC(mib2.icmpoutmsgs);

  /* ICMP header + IP header + 8 bytes of data */
  q = pbuf_alloc(PBUF_IP, sizeof(struct icmp_echo_hdr) + IP_HLEN + ICMP_DEST_UNREACH_DATASIZE,
                 PBUF_RAM);
  if (q == NULL) {
    MIB2_STATS_INC(mib2.icmpouterrors);
    return;
  }
  
  iphdr = (struct ip_hdr *)p->payload;
  ip4_addr_debug_print_val(ICMP_DEBUG, iphdr->src);
  ip4_addr_debug_print_val(ICMP_DEBUG, iphdr->dest);
  
  icmphdr = (struct icmp_echo_hdr *)q->payload;
  icmphdr->type = type;
  icmphdr->code = code;
  icmphdr->id = 0;
  icmphdr->seqno = 0;

  /* copy fields from original packet */
  SMEMCPY((u8_t *)q->payload + sizeof(struct icmp_echo_hdr), (u8_t *)p->payload,
          IP_HLEN + ICMP_DEST_UNREACH_DATASIZE);

  ip4_addr_copy(iphdr_src, iphdr->src);
#ifdef LWIP_HOOK_IP4_ROUTE_SRC
  {
    ip4_addr_t iphdr_dst;
    ip4_addr_copy(iphdr_dst, iphdr->dest);
    netif = ip4_route_src(&iphdr_dst, &iphdr_src);
  }
#else
  netif = ip4_route(&iphdr_src);
#endif
  if (netif != NULL) {
    /* calculate checksum */
    icmphdr->chksum = 0;
#if CHECKSUM_GEN_ICMP
    IF__NETIF_CHECKSUM_ENABLED(netif, NETIF_CHECKSUM_GEN_ICMP) {
      icmphdr->chksum = inet_chksum(icmphdr, q->len);
    }
#endif
    ICMP_STATS_INC(icmp.xmit);
    ip4_output_if(q, NULL, &iphdr_src, ICMP_TTL, 0, IP_PROTO_ICMP, netif);
  }
  pbuf_free(q);
}

#endif /* LWIP_IPV4 && LWIP_ICMP */
```

### 5）接收

```C++
void
icmp_input(struct pbuf *p, struct netif *inp)
{
  u8_t type;

  struct icmp_echo_hdr *iecho;
  const struct ip_hdr *iphdr_in;
  u16_t hlen;
  const ip4_addr_t *src;

  ICMP_STATS_INC(icmp.recv);
  MIB2_STATS_INC(mib2.icmpinmsgs);

  iphdr_in = ip4_current_header();
  hlen = IPH_HL_BYTES(iphdr_in);
  if (hlen < IP_HLEN) {
    goto lenerr;
  }
  if (p->len < sizeof(u16_t) * 2) {
    goto lenerr;
  }

  type = *((u8_t *)p->payload);
  switch (type) {
    case ICMP_ER:
      /* This is OK, echo reply might have been parsed by a raw PCB
         (as obviously, an echo request has been sent, too). */
      MIB2_STATS_INC(mib2.icmpinechoreps);
      break;
    case ICMP_ECHO:
      MIB2_STATS_INC(mib2.icmpinechos);
      src = ip4_current_dest_addr();
      /* multicast destination address? */
      if (ip4_addr_ismulticast(ip4_current_dest_addr())) {
#if LWIP_MULTICAST_PING
        /* For multicast, use address of receiving interface as source address */
        src = netif_ip4_addr(inp);
#else /* LWIP_MULTICAST_PING */
        goto icmperr;
#endif /* LWIP_MULTICAST_PING */
      }
      /* broadcast destination address? */
      if (ip4_addr_isbroadcast(ip4_current_dest_addr(), ip_current_netif())) {
#if LWIP_BROADCAST_PING
        /* For broadcast, use address of receiving interface as source address */
        src = netif_ip4_addr(inp);
#else /* LWIP_BROADCAST_PING */
        goto icmperr;
#endif /* LWIP_BROADCAST_PING */
      }
      if (p->tot_len < sizeof(struct icmp_echo_hdr)) {
        goto lenerr;
      }
#if CHECKSUM_CHECK_ICMP
      IF__NETIF_CHECKSUM_ENABLED(inp, NETIF_CHECKSUM_CHECK_ICMP) {
        if (inet_chksum_pbuf(p) != 0) {
          pbuf_free(p);
          ICMP_STATS_INC(icmp.chkerr);
          MIB2_STATS_INC(mib2.icmpinerrors);
          return;
        }
      }
#endif
#if LWIP_ICMP_ECHO_CHECK_INPUT_PBUF_LEN
      if (pbuf_add_header(p, hlen + PBUF_LINK_HLEN + PBUF_LINK_ENCAPSULATION_HLEN)) {
        /* p is not big enough to contain link headers
         * allocate a new one and copy p into it
         */
        struct pbuf *r;
        u16_t alloc_len = (u16_t)(p->tot_len + hlen);
        if (alloc_len < p->tot_len) {
          goto icmperr;
        }
        /* allocate new packet buffer with space for link headers */
        r = pbuf_alloc(PBUF_LINK, alloc_len, PBUF_RAM);
        if (r == NULL) {
          goto icmperr;
        }
        if (r->len < hlen + sizeof(struct icmp_echo_hdr)) {
          pbuf_free(r);
          goto icmperr;
        }
        /* copy the ip header */
        MEMCPY(r->payload, iphdr_in, hlen);
        /* switch r->payload back to icmp header (cannot fail) */
        if (pbuf_remove_header(r, hlen)) {
          pbuf_free(r);
          goto icmperr;
        }
        /* copy the rest of the packet without ip header */
        if (pbuf_copy(r, p) != ERR_OK) {
          pbuf_free(r);
          goto icmperr;
        }
        /* free the original p */
        pbuf_free(p);
        /* we now have an identical copy of p that has room for link headers */
        p = r;
      } else {
        /* restore p->payload to point to icmp header (cannot fail) */
        if (pbuf_remove_header(p, hlen + PBUF_LINK_HLEN + PBUF_LINK_ENCAPSULATION_HLEN)) {
          goto icmperr;
        }
      }
#endif /* LWIP_ICMP_ECHO_CHECK_INPUT_PBUF_LEN */
      /* At this point, all checks are OK. */
      /* We generate an answer by switching the dest and src ip addresses,
       * setting the icmp type to ECHO_RESPONSE and updating the checksum. */
      iecho = (struct icmp_echo_hdr *)p->payload;
      if (pbuf_add_header(p, hlen)) {
        
      } else {
        err_t ret;
        struct ip_hdr *iphdr = (struct ip_hdr *)p->payload;
        ip4_addr_copy(iphdr->src, *src);
        ip4_addr_copy(iphdr->dest, *ip4_current_src_addr());
        ICMPH_TYPE_SET(iecho, ICMP_ER);
#if CHECKSUM_GEN_ICMP
        IF__NETIF_CHECKSUM_ENABLED(inp, NETIF_CHECKSUM_GEN_ICMP) {
          /* adjust the checksum */
          if (iecho->chksum > PP_HTONS(0xffffU - (ICMP_ECHO << 8))) {
            iecho->chksum = (u16_t)(iecho->chksum + PP_HTONS((u16_t)(ICMP_ECHO << 8)) + 1);
          } else {
            iecho->chksum = (u16_t)(iecho->chksum + PP_HTONS(ICMP_ECHO << 8));
          }
        }
#if LWIP_CHECKSUM_CTRL_PER_NETIF
        else {
          iecho->chksum = 0;
        }
#endif /* LWIP_CHECKSUM_CTRL_PER_NETIF */
#else /* CHECKSUM_GEN_ICMP */
        iecho->chksum = 0;
#endif /* CHECKSUM_GEN_ICMP */

        /* Set the correct TTL and recalculate the header checksum. */
        IPH_TTL_SET(iphdr, ICMP_TTL);
        IPH_CHKSUM_SET(iphdr, 0);
#if CHECKSUM_GEN_IP
        IF__NETIF_CHECKSUM_ENABLED(inp, NETIF_CHECKSUM_GEN_IP) {
          IPH_CHKSUM_SET(iphdr, inet_chksum(iphdr, hlen));
        }
#endif /* CHECKSUM_GEN_IP */

        ICMP_STATS_INC(icmp.xmit);
        /* increase number of messages attempted to send */
        MIB2_STATS_INC(mib2.icmpoutmsgs);
        /* increase number of echo replies attempted to send */
        MIB2_STATS_INC(mib2.icmpoutechoreps);

        /* send an ICMP packet */
        ret = ip4_output_if(p, src, LWIP_IP_HDRINCL,
                            ICMP_TTL, 0, IP_PROTO_ICMP, inp);
        if (ret != ERR_OK) {
          
        }
      }
      break;
    default:
      if (type == ICMP_DUR) {
        MIB2_STATS_INC(mib2.icmpindestunreachs);
      } else if (type == ICMP_TE) {
        MIB2_STATS_INC(mib2.icmpintimeexcds);
      } else if (type == ICMP_PP) {
        MIB2_STATS_INC(mib2.icmpinparmprobs);
      } else if (type == ICMP_SQ) {
        MIB2_STATS_INC(mib2.icmpinsrcquenchs);
      } else if (type == ICMP_RD) {
        MIB2_STATS_INC(mib2.icmpinredirects);
      } else if (type == ICMP_TS) {
        MIB2_STATS_INC(mib2.icmpintimestamps);
      } else if (type == ICMP_TSR) {
        MIB2_STATS_INC(mib2.icmpintimestampreps);
      } else if (type == ICMP_AM) {
        MIB2_STATS_INC(mib2.icmpinaddrmasks);
      } else if (type == ICMP_AMR) {
        MIB2_STATS_INC(mib2.icmpinaddrmaskreps);
      }
      ICMP_STATS_INC(icmp.proterr);
      ICMP_STATS_INC(icmp.drop);
  }
  pbuf_free(p);
  return;
lenerr:
  pbuf_free(p);
  ICMP_STATS_INC(icmp.lenerr);
  MIB2_STATS_INC(mib2.icmpinerrors);
  return;
#if LWIP_ICMP_ECHO_CHECK_INPUT_PBUF_LEN || !LWIP_MULTICAST_PING || !LWIP_BROADCAST_PING
icmperr:
  pbuf_free(p);
  ICMP_STATS_INC(icmp.err);
  MIB2_STATS_INC(mib2.icmpinerrors);
  return;
#endif /* LWIP_ICMP_ECHO_CHECK_INPUT_PBUF_LEN || !LWIP_MULTICAST_PING || !LWIP_BROADCAST_PING */
}
```

## 13、TCP协议

### 1）简介

- 特性
  - 复杂：TCP协议的处理占据了LwIP协议栈的大半代码
  - 连接机制
  - 确认和重传
  - 缓冲机制
  - 全双工通信
  - 流量控制
    - 滑动窗口：接收方告知发送端还能接收多少数据
  - 差错控制
    - 校验
    - 排重
    - 乱序重组
    - 重传
  - 拥塞控制
    - 延迟重传
- 常用端口
  - 20、21：FTP
  - 25：SMTP
  - 69：TFTP
  - 80：HTTP
  - 110：POP3

### 2）TCP报文结构

![image-20200313150206088](images\LwIP\TCP报文封装.png)

![image-20200313150134539](images\LwIP\TCP报文结构.png)

```C++
PACK_STRUCT_BEGIN
struct tcp_hdr {
  PACK_STRUCT_FIELD(u16_t src);
  PACK_STRUCT_FIELD(u16_t dest);
  PACK_STRUCT_FIELD(u32_t seqno);
  PACK_STRUCT_FIELD(u32_t ackno);
  PACK_STRUCT_FIELD(u16_t _hdrlen_rsvd_flags);
  PACK_STRUCT_FIELD(u16_t wnd);
  PACK_STRUCT_FIELD(u16_t chksum);
  PACK_STRUCT_FIELD(u16_t urgp);
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END
```

- URG：紧急标志，为1表示紧急指针字段有效。
- ACK：确认标志，为1表示确认序号字段有效。
- PSH：上传标志，为1表示尽快交给应用层。
- RST：重置标志，为1表示需要重新建立 TCP 连接。
- SYN：同步标志，为1表示发起连接。
- FIN：中止标志，为1表示中止连接。
- 窗口大小：单位字节，0表示阻止发送方的数据发送
- 序号
  - 开启TCP回话时，初始序号ISN是随机的
  - Wireshark为方便查看，显示的为相对序号
  - 连接和断开：+1处理
  - 正常传输时：每次加上数据长度
![image-20200313165443051](D:\Book\StudyNote\images\LwIP\序号说明.png)

### 3）三次握手

![image-20200313164829141](images\LwIP\三次握手.png)

### 4）四次挥手

- TCP为全双工，两个方向都要单独关闭

![image-20200313164930902](images\LwIP\四次挥手.png)

### 5）状态转换

![image-20200313170623819](images\LwIP\tcp状态转换.png)

### 6）PCB

```C++
#define TCP_PCB_COMMON(type) \
  type *next; /* for the linked list */ \
  void *callback_arg; \
  TCP_PCB_EXTARGS \
  enum tcp_state state; /* TCP state */ \
  u8_t prio; \
  /* ports are in host byte order */ \
  u16_t local_port
      
/** the TCP protocol control block */
struct tcp_pcb {
/** common PCB members */
  IP_PCB;
/** protocol specific PCB members */
  TCP_PCB_COMMON(struct tcp_pcb);

  /* ports are in host byte order */
  u16_t remote_port;

  tcpflags_t flags;
#define TF_ACK_DELAY   0x01U   /* Delayed ACK. */
#define TF_ACK_NOW     0x02U   /* Immediate ACK. */
#define TF_INFR        0x04U   /* In fast recovery. */
#define TF_CLOSEPEND   0x08U   /* If this is set, tcp_close failed to enqueue the FIN (retried in tcp_tmr) */
#define TF_RXCLOSED    0x10U   /* rx closed by tcp_shutdown */
#define TF_FIN         0x20U   /* Connection was closed locally (FIN segment enqueued). */
#define TF_NODELAY     0x40U   /* Disable Nagle algorithm */
#define TF_NAGLEMEMERR 0x80U   /* nagle enabled, memerr, try to output to prevent delayed ACK to happen */
#if LWIP_WND_SCALE
#define TF_WND_SCALE   0x0100U /* Window Scale option enabled */
#endif
#if TCP_LISTEN_BACKLOG
#define TF_BACKLOGPEND 0x0200U /* If this is set, a connection pcb has increased the backlog on its listener */
#endif
#if LWIP_TCP_TIMESTAMPS
#define TF_TIMESTAMP   0x0400U   /* Timestamp option enabled */
#endif
#define TF_RTO         0x0800U /* RTO timer has fired, in-flight data moved to unsent and being retransmitted */
#if LWIP_TCP_SACK_OUT
#define TF_SACK        0x1000U /* Selective ACKs enabled */
#endif

  /* the rest of the fields are in host byte order
     as we have to do some math with them */

  /* Timers */
  u8_t polltmr, pollinterval;
  u8_t last_timer;
  u32_t tmr;

  /* receiver variables */
  u32_t rcv_nxt;   /* next seqno expected */
  tcpwnd_size_t rcv_wnd;   /* receiver window available */
  tcpwnd_size_t rcv_ann_wnd; /* receiver window to announce */
  u32_t rcv_ann_right_edge; /* announced right edge of window */

#if LWIP_TCP_SACK_OUT
  /* SACK ranges to include in ACK packets (entry is invalid if left==right) */
  struct tcp_sack_range rcv_sacks[LWIP_TCP_MAX_SACK_NUM];
#define LWIP_TCP_SACK_VALID(pcb, idx) ((pcb)->rcv_sacks[idx].left != (pcb)->rcv_sacks[idx].right)
#endif /* LWIP_TCP_SACK_OUT */

  /* Retransmission timer. */
  s16_t rtime;

  u16_t mss;   /* maximum segment size */

  /* RTT (round trip time) estimation variables */
  u32_t rttest; /* RTT estimate in 500ms ticks */
  u32_t rtseq;  /* sequence number being timed */
  s16_t sa, sv; /* @see "Congestion Avoidance and Control" by Van Jacobson and Karels */

  s16_t rto;    /* retransmission time-out (in ticks of TCP_SLOW_INTERVAL) */
  u8_t nrtx;    /* number of retransmissions */

  /* fast retransmit/recovery */
  u8_t dupacks;
  u32_t lastack; /* Highest acknowledged seqno. */

  /* congestion avoidance/control variables */
  tcpwnd_size_t cwnd;
  tcpwnd_size_t ssthresh;

  /* first byte following last rto byte */
  u32_t rto_end;

  /* sender variables */
  u32_t snd_nxt;   /* next new seqno to be sent */
  u32_t snd_wl1, snd_wl2; /* Sequence and acknowledgement numbers of last
                             window update. */
  u32_t snd_lbb;       /* Sequence number of next byte to be buffered. */
  tcpwnd_size_t snd_wnd;   /* sender window */
  tcpwnd_size_t snd_wnd_max; /* the maximum sender window announced by the remote host */

  tcpwnd_size_t snd_buf;   /* Available buffer space for sending (in bytes). */
#define TCP_SNDQUEUELEN_OVERFLOW (0xffffU-3)
  u16_t snd_queuelen; /* Number of pbufs currently in the send buffer. */

#if TCP_OVERSIZE
  /* Extra bytes available at the end of the last pbuf in unsent. */
  u16_t unsent_oversize;
#endif /* TCP_OVERSIZE */

  tcpwnd_size_t bytes_acked;

  /* These are ordered by sequence number: */
  struct tcp_seg *unsent;   /* Unsent (queued) segments. */
  struct tcp_seg *unacked;  /* Sent but unacknowledged segments. */
#if TCP_QUEUE_OOSEQ
  struct tcp_seg *ooseq;    /* Received out of sequence segments. */
#endif /* TCP_QUEUE_OOSEQ */

  struct pbuf *refused_data; /* Data previously received but not yet taken by upper layer */

#if LWIP_CALLBACK_API || TCP_LISTEN_BACKLOG
  struct tcp_pcb_listen* listener;
#endif /* LWIP_CALLBACK_API || TCP_LISTEN_BACKLOG */

#if LWIP_CALLBACK_API
  /* Function to be called when more send buffer space is available. */
  tcp_sent_fn sent;
  /* Function to be called when (in-sequence) data has arrived. */
  tcp_recv_fn recv;
  /* Function to be called when a connection has been set up. */
  tcp_connected_fn connected;
  /* Function which is called periodically. */
  tcp_poll_fn poll;
  /* Function to be called whenever a fatal error occurs. */
  tcp_err_fn errf;
#endif /* LWIP_CALLBACK_API */

#if LWIP_TCP_TIMESTAMPS
  u32_t ts_lastacksent;
  u32_t ts_recent;
#endif /* LWIP_TCP_TIMESTAMPS */

  /* idle time before KEEPALIVE is sent */
  u32_t keep_idle;
#if LWIP_TCP_KEEPALIVE
  u32_t keep_intvl;
  u32_t keep_cnt;
#endif /* LWIP_TCP_KEEPALIVE */

  /* Persist timer counter */
  u8_t persist_cnt;
  /* Persist timer back-off */
  u8_t persist_backoff;
  /* Number of persist probes */
  u8_t persist_probe;

  /* KEEPALIVE counter */
  u8_t keep_cnt_sent;

#if LWIP_WND_SCALE
  u8_t snd_scale;
  u8_t rcv_scale;
#endif
};
```

### 7）接收窗口

![image-20200313171834361](images\LwIP\接收窗口.png)

### 8）发送窗口

![image-20200313171920222](images\LwIP\发送窗口.png)

### 9）报文段缓冲队列

```C++
/* This structure represents a TCP segment on the unsent, unacked and ooseq queues */
struct tcp_seg {
  struct tcp_seg *next;    /* used when putting segments on a queue */
  struct pbuf *p;          /* buffer containing data + TCP header */
  u16_t len;               /* the TCP length of this segment */

  u8_t  flags;
#define TF_SEG_OPTS_MSS         (u8_t)0x01U /* Include MSS option (only used in SYN segments) */
#define TF_SEG_OPTS_TS          (u8_t)0x02U /* Include timestamp option. */
#define TF_SEG_DATA_CHECKSUMMED (u8_t)0x04U /* ALL data (not the header) is
                                               checksummed into 'chksum' */
#define TF_SEG_OPTS_WND_SCALE   (u8_t)0x08U /* Include WND SCALE option (only used in SYN segments) */
#define TF_SEG_OPTS_SACK_PERM   (u8_t)0x10U /* Include SACK Permitted option (only used in SYN segments) */
  struct tcp_hdr *tcphdr;  /* the TCP header */
};
```

![image-20200313173625092](images\LwIP\tcp报文缓存队列管理.png)

### 10）发送

```C++
err_t
tcp_output(struct tcp_pcb *pcb)
{
  struct tcp_seg *seg, *useg;
  u32_t wnd, snd_nxt;
  err_t err;
  struct netif *netif;

  /* First, check if we are invoked by the TCP input processing
     code. If so, we do not output anything. Instead, we rely on the
     input processing code to call us when input processing is done
     with. */
  if (tcp_input_pcb == pcb) {
    return ERR_OK;
  }

  wnd = LWIP_MIN(pcb->snd_wnd, pcb->cwnd);

  seg = pcb->unsent;

  netif = tcp_route(pcb, &pcb->local_ip, &pcb->remote_ip);
  if (netif == NULL) {
    return ERR_RTE;
  }

  /* If we don't have a local IP address, we get one from netif */
  if (ip_addr_isany(&pcb->local_ip)) {
    const ip_addr_t *local_ip = ip_netif_get_local_ip(netif, &pcb->remote_ip);
    if (local_ip == NULL) {
      return ERR_RTE;
    }
    ip_addr_copy(pcb->local_ip, *local_ip);
  }

  /* Handle the current segment not fitting within the window */
  if (lwip_ntohl(seg->tcphdr->seqno) - pcb->lastack + seg->len > wnd) {
    /* We need to start the persistent timer when the next unsent segment does not fit
     * within the remaining (could be 0) send window and RTO timer is not running (we
     * have no in-flight data). If window is still too small after persist timer fires,
     * then we split the segment. We don't consider the congestion window since a cwnd
     * smaller than 1 SMSS implies in-flight data
     */
    if (wnd == pcb->snd_wnd && pcb->unacked == NULL && pcb->persist_backoff == 0) {
      pcb->persist_cnt = 0;
      pcb->persist_backoff = 1;
      pcb->persist_probe = 0;
    }
    /* We need an ACK, but can't send data now, so send an empty ACK */
    if (pcb->flags & TF_ACK_NOW) {
      return tcp_send_empty_ack(pcb);
    }
    goto output_done;
  }
  /* Stop persist timer, above conditions are not active */
  pcb->persist_backoff = 0;

  /* useg should point to last segment on unacked queue */
  useg = pcb->unacked;
  if (useg != NULL) {
    for (; useg->next != NULL; useg = useg->next);
  }
  /* data available and window allows it to be sent? */
  while (seg != NULL &&
         lwip_ntohl(seg->tcphdr->seqno) - pcb->lastack + seg->len <= wnd) {
    /* Stop sending if the nagle algorithm would prevent it
     * Don't stop:
     * - if tcp_write had a memory error before (prevent delayed ACK timeout) or
     * - if FIN was already enqueued for this PCB (SYN is always alone in a segment -
     *   either seg->next != NULL or pcb->unacked == NULL;
     *   RST is no sent using tcp_write/tcp_output.
     */
    if ((tcp_do_output_nagle(pcb) == 0) &&
        ((pcb->flags & (TF_NAGLEMEMERR | TF_FIN)) == 0)) {
      break;
    }

    if (pcb->state != SYN_SENT) {
      TCPH_SET_FLAG(seg->tcphdr, TCP_ACK);
    }

    err = tcp_output_segment(seg, pcb, netif);
    if (err != ERR_OK) {
      /* segment could not be sent, for whatever reason */
      tcp_set_flags(pcb, TF_NAGLEMEMERR);
      return err;
    }
#if TCP_OVERSIZE_DBGCHECK
    seg->oversize_left = 0;
#endif /* TCP_OVERSIZE_DBGCHECK */
    pcb->unsent = seg->next;
    if (pcb->state != SYN_SENT) {
      tcp_clear_flags(pcb, TF_ACK_DELAY | TF_ACK_NOW);
    }
    snd_nxt = lwip_ntohl(seg->tcphdr->seqno) + TCP_TCPLEN(seg);
    if (TCP_SEQ_LT(pcb->snd_nxt, snd_nxt)) {
      pcb->snd_nxt = snd_nxt;
    }
    /* put segment on unacknowledged list if length > 0 */
    if (TCP_TCPLEN(seg) > 0) {
      seg->next = NULL;
      /* unacked list is empty? */
      if (pcb->unacked == NULL) {
        pcb->unacked = seg;
        useg = seg;
        /* unacked list is not empty? */
      } else {
        /* In the case of fast retransmit, the packet should not go to the tail
         * of the unacked queue, but rather somewhere before it. We need to check for
         * this case. -STJ Jul 27, 2004 */
        if (TCP_SEQ_LT(lwip_ntohl(seg->tcphdr->seqno), lwip_ntohl(useg->tcphdr->seqno))) {
          /* add segment to before tail of unacked list, keeping the list sorted */
          struct tcp_seg **cur_seg = &(pcb->unacked);
          while (*cur_seg &&
                 TCP_SEQ_LT(lwip_ntohl((*cur_seg)->tcphdr->seqno), lwip_ntohl(seg->tcphdr->seqno))) {
            cur_seg = &((*cur_seg)->next );
          }
          seg->next = (*cur_seg);
          (*cur_seg) = seg;
        } else {
          /* add segment to tail of unacked list */
          useg->next = seg;
          useg = useg->next;
        }
      }
      /* do not queue empty segments on the unacked list */
    } else {
      tcp_seg_free(seg);
    }
    seg = pcb->unsent;
  }
#if TCP_OVERSIZE
  if (pcb->unsent == NULL) {
    /* last unsent has been removed, reset unsent_oversize */
    pcb->unsent_oversize = 0;
  }
#endif /* TCP_OVERSIZE */

output_done:
  tcp_clear_flags(pcb, TF_NAGLEMEMERR);
  return ERR_OK;
}
```

### 11）接收

```c++
void
tcp_input(struct pbuf *p, struct netif *inp)
{
  struct tcp_pcb *pcb, *prev;
  struct tcp_pcb_listen *lpcb;
#if SO_REUSE
  struct tcp_pcb *lpcb_prev = NULL;
  struct tcp_pcb_listen *lpcb_any = NULL;
#endif /* SO_REUSE */
  u8_t hdrlen_bytes;
  err_t err;

  LWIP_UNUSED_ARG(inp);
  
  PERF_START;

  TCP_STATS_INC(tcp.recv);
  MIB2_STATS_INC(mib2.tcpinsegs);

  tcphdr = (struct tcp_hdr *)p->payload;

#if TCP_INPUT_DEBUG
  tcp_debug_print(tcphdr);
#endif

  /* Check that TCP header fits in payload */
  if (p->len < TCP_HLEN) {
    /* drop short packets */
    
    TCP_STATS_INC(tcp.lenerr);
    goto dropped;
  }

  /* Don't even process incoming broadcasts/multicasts. */
  if (ip_addr_isbroadcast(ip_current_dest_addr(), ip_current_netif()) ||
      ip_addr_ismulticast(ip_current_dest_addr())) {
    TCP_STATS_INC(tcp.proterr);
    goto dropped;
  }

#if CHECKSUM_CHECK_TCP
  IF__NETIF_CHECKSUM_ENABLED(inp, NETIF_CHECKSUM_CHECK_TCP) {
    /* Verify TCP checksum. */
    u16_t chksum = ip_chksum_pseudo(p, IP_PROTO_TCP, p->tot_len,
                                    ip_current_src_addr(), ip_current_dest_addr());
    if (chksum != 0) {
      
      tcp_debug_print(tcphdr);
      TCP_STATS_INC(tcp.chkerr);
      goto dropped;
    }
  }
#endif /* CHECKSUM_CHECK_TCP */

  /* sanity-check header length */
  hdrlen_bytes = TCPH_HDRLEN_BYTES(tcphdr);
  if ((hdrlen_bytes < TCP_HLEN) || (hdrlen_bytes > p->tot_len)) {
    
    TCP_STATS_INC(tcp.lenerr);
    goto dropped;
  }

  /* Move the payload pointer in the pbuf so that it points to the
     TCP data instead of the TCP header. */
  tcphdr_optlen = (u16_t)(hdrlen_bytes - TCP_HLEN);
  tcphdr_opt2 = NULL;
  if (p->len >= hdrlen_bytes) {
    /* all options are in the first pbuf */
    tcphdr_opt1len = tcphdr_optlen;
    pbuf_remove_header(p, hdrlen_bytes); /* cannot fail */
  } else {
    u16_t opt2len;
    /* TCP header fits into first pbuf, options don't - data is in the next pbuf */
    /* there must be a next pbuf, due to hdrlen_bytes sanity check above */
    
    /* advance over the TCP header (cannot fail) */
    pbuf_remove_header(p, TCP_HLEN);

    /* determine how long the first and second parts of the options are */
    tcphdr_opt1len = p->len;
    opt2len = (u16_t)(tcphdr_optlen - tcphdr_opt1len);

    /* options continue in the next pbuf: set p to zero length and hide the
        options in the next pbuf (adjusting p->tot_len) */
    pbuf_remove_header(p, tcphdr_opt1len);

    /* check that the options fit in the second pbuf */
    if (opt2len > p->next->len) {
      /* drop short packets */
      
      TCP_STATS_INC(tcp.lenerr);
      goto dropped;
    }

    /* remember the pointer to the second part of the options */
    tcphdr_opt2 = (u8_t *)p->next->payload;

    /* advance p->next to point after the options, and manually
        adjust p->tot_len to keep it consistent with the changed p->next */
    pbuf_remove_header(p->next, opt2len);
    p->tot_len = (u16_t)(p->tot_len - opt2len);    
  }

  /* Convert fields in TCP header to host byte order. */
  tcphdr->src = lwip_ntohs(tcphdr->src);
  tcphdr->dest = lwip_ntohs(tcphdr->dest);
  seqno = tcphdr->seqno = lwip_ntohl(tcphdr->seqno);
  ackno = tcphdr->ackno = lwip_ntohl(tcphdr->ackno);
  tcphdr->wnd = lwip_ntohs(tcphdr->wnd);

  flags = TCPH_FLAGS(tcphdr);
  tcplen = p->tot_len;
  if (flags & (TCP_FIN | TCP_SYN)) {
    tcplen++;
    if (tcplen < p->tot_len) {
      /* u16_t overflow, cannot handle this */
      
      TCP_STATS_INC(tcp.lenerr);
      goto dropped;
    }
  }

  /* Demultiplex an incoming segment. First, we check if it is destined
     for an active connection. */
  prev = NULL;

  for (pcb = tcp_active_pcbs; pcb != NULL; pcb = pcb->next) {
    
    /* check if PCB is bound to specific netif */
    if ((pcb->netif_idx != NETIF_NO_INDEX) &&
        (pcb->netif_idx != netif_get_index(ip_data.current_input_netif))) {
      prev = pcb;
      continue;
    }

    if (pcb->remote_port == tcphdr->src &&
        pcb->local_port == tcphdr->dest &&
        ip_addr_cmp(&pcb->remote_ip, ip_current_src_addr()) &&
        ip_addr_cmp(&pcb->local_ip, ip_current_dest_addr())) {
      /* Move this PCB to the front of the list so that subsequent
         lookups will be faster (we exploit locality in TCP segment
         arrivals). */
      if (prev != NULL) {
        prev->next = pcb->next;
        pcb->next = tcp_active_pcbs;
        tcp_active_pcbs = pcb;
      } else {
        TCP_STATS_INC(tcp.cachehit);
      }
      break;
    }
    prev = pcb;
  }

  if (pcb == NULL) {
    /* If it did not go to an active connection, we check the connections
       in the TIME-WAIT state. */
    for (pcb = tcp_tw_pcbs; pcb != NULL; pcb = pcb->next) {
      
      /* check if PCB is bound to specific netif */
      if ((pcb->netif_idx != NETIF_NO_INDEX) &&
          (pcb->netif_idx != netif_get_index(ip_data.current_input_netif))) {
        continue;
      }

      if (pcb->remote_port == tcphdr->src &&
          pcb->local_port == tcphdr->dest &&
          ip_addr_cmp(&pcb->remote_ip, ip_current_src_addr()) &&
          ip_addr_cmp(&pcb->local_ip, ip_current_dest_addr())) {
        /* We don't really care enough to move this PCB to the front
           of the list since we are not very likely to receive that
           many segments for connections in TIME-WAIT. */
        
#ifdef LWIP_HOOK_TCP_INPACKET_PCB
        if (LWIP_HOOK_TCP_INPACKET_PCB(pcb, tcphdr, tcphdr_optlen, tcphdr_opt1len,
                                       tcphdr_opt2, p) == ERR_OK)
#endif
        {
          tcp_timewait_input(pcb);
        }
        pbuf_free(p);
        return;
      }
    }

    /* Finally, if we still did not get a match, we check all PCBs that
       are LISTENing for incoming connections. */
    prev = NULL;
    for (lpcb = tcp_listen_pcbs.listen_pcbs; lpcb != NULL; lpcb = lpcb->next) {
      /* check if PCB is bound to specific netif */
      if ((lpcb->netif_idx != NETIF_NO_INDEX) &&
          (lpcb->netif_idx != netif_get_index(ip_data.current_input_netif))) {
        prev = (struct tcp_pcb *)lpcb;
        continue;
      }

      if (lpcb->local_port == tcphdr->dest) {
        if (IP_IS_ANY_TYPE_VAL(lpcb->local_ip)) {
          /* found an ANY TYPE (IPv4/IPv6) match */
#if SO_REUSE
          lpcb_any = lpcb;
          lpcb_prev = prev;
#else /* SO_REUSE */
          break;
#endif /* SO_REUSE */
        } else if (IP_ADDR_PCB_VERSION_MATCH_EXACT(lpcb, ip_current_dest_addr())) {
          if (ip_addr_cmp(&lpcb->local_ip, ip_current_dest_addr())) {
            /* found an exact match */
            break;
          } else if (ip_addr_isany(&lpcb->local_ip)) {
            /* found an ANY-match */
#if SO_REUSE
            lpcb_any = lpcb;
            lpcb_prev = prev;
#else /* SO_REUSE */
            break;
#endif /* SO_REUSE */
          }
        }
      }
      prev = (struct tcp_pcb *)lpcb;
    }
#if SO_REUSE
    /* first try specific local IP */
    if (lpcb == NULL) {
      /* only pass to ANY if no specific local IP has been found */
      lpcb = lpcb_any;
      prev = lpcb_prev;
    }
#endif /* SO_REUSE */
    if (lpcb != NULL) {
      /* Move this PCB to the front of the list so that subsequent
         lookups will be faster (we exploit locality in TCP segment
         arrivals). */
      if (prev != NULL) {
        ((struct tcp_pcb_listen *)prev)->next = lpcb->next;
        /* our successor is the remainder of the listening list */
        lpcb->next = tcp_listen_pcbs.listen_pcbs;
        /* put this listening pcb at the head of the listening list */
        tcp_listen_pcbs.listen_pcbs = lpcb;
      } else {
        TCP_STATS_INC(tcp.cachehit);
      }
      
#ifdef LWIP_HOOK_TCP_INPACKET_PCB
      if (LWIP_HOOK_TCP_INPACKET_PCB((struct tcp_pcb *)lpcb, tcphdr, tcphdr_optlen,
                                     tcphdr_opt1len, tcphdr_opt2, p) == ERR_OK)
#endif
      {
        tcp_listen_input(lpcb);
      }
      pbuf_free(p);
      return;
    }
  }

#ifdef LWIP_HOOK_TCP_INPACKET_PCB
  if ((pcb != NULL) && LWIP_HOOK_TCP_INPACKET_PCB(pcb, tcphdr, tcphdr_optlen,
      tcphdr_opt1len, tcphdr_opt2, p) != ERR_OK) {
    pbuf_free(p);
    return;
  }
#endif
  if (pcb != NULL) {
    /* The incoming segment belongs to a connection. */
#if TCP_INPUT_DEBUG
    tcp_debug_print_state(pcb->state);
#endif /* TCP_INPUT_DEBUG */

    /* Set up a tcp_seg structure. */
    inseg.next = NULL;
    inseg.len = p->tot_len;
    inseg.p = p;
    inseg.tcphdr = tcphdr;

    recv_data = NULL;
    recv_flags = 0;
    recv_acked = 0;

    if (flags & TCP_PSH) {
      p->flags |= PBUF_FLAG_PUSH;
    }

    /* If there is data which was previously "refused" by upper layer */
    if (pcb->refused_data != NULL) {
      if ((tcp_process_refused_data(pcb) == ERR_ABRT) ||
          ((pcb->refused_data != NULL) && (tcplen > 0))) {
        /* pcb has been aborted or refused data is still refused and the new
           segment contains data */
        if (pcb->rcv_ann_wnd == 0) {
          /* this is a zero-window probe, we respond to it with current RCV.NXT
          and drop the data segment */
          tcp_send_empty_ack(pcb);
        }
        TCP_STATS_INC(tcp.drop);
        MIB2_STATS_INC(mib2.tcpinerrs);
        goto aborted;
      }
    }
    tcp_input_pcb = pcb;
    err = tcp_process(pcb);
    /* A return value of ERR_ABRT means that tcp_abort() was called
       and that the pcb has been freed. If so, we don't do anything. */
    if (err != ERR_ABRT) {
      if (recv_flags & TF_RESET) {
        /* TF_RESET means that the connection was reset by the other
           end. We then call the error callback to inform the
           application that the connection is dead before we
           deallocate the PCB. */
        TCP_EVENT_ERR(pcb->state, pcb->errf, pcb->callback_arg, ERR_RST);
        tcp_pcb_remove(&tcp_active_pcbs, pcb);
        tcp_free(pcb);
      } else {
        err = ERR_OK;
        /* If the application has registered a "sent" function to be
           called when new send buffer space is available, we call it
           now. */
        if (recv_acked > 0) {
          u16_t acked16;
#if LWIP_WND_SCALE
          /* recv_acked is u32_t but the sent callback only takes a u16_t,
             so we might have to call it multiple times. */
          u32_t acked = recv_acked;
          while (acked > 0) {
            acked16 = (u16_t)LWIP_MIN(acked, 0xffffu);
            acked -= acked16;
#else
          {
            acked16 = recv_acked;
#endif
            TCP_EVENT_SENT(pcb, (u16_t)acked16, err);
            if (err == ERR_ABRT) {
              goto aborted;
            }
          }
          recv_acked = 0;
        }
        if (tcp_input_delayed_close(pcb)) {
          goto aborted;
        }
#if TCP_QUEUE_OOSEQ && LWIP_WND_SCALE
        while (recv_data != NULL) {
          struct pbuf *rest = NULL;
          pbuf_split_64k(recv_data, &rest);
#else /* TCP_QUEUE_OOSEQ && LWIP_WND_SCALE */
        if (recv_data != NULL) {
#endif /* TCP_QUEUE_OOSEQ && LWIP_WND_SCALE */

          if (pcb->flags & TF_RXCLOSED) {
            /* received data although already closed -> abort (send RST) to
               notify the remote host that not all data has been processed */
            pbuf_free(recv_data);
#if TCP_QUEUE_OOSEQ && LWIP_WND_SCALE
            if (rest != NULL) {
              pbuf_free(rest);
            }
#endif /* TCP_QUEUE_OOSEQ && LWIP_WND_SCALE */
            tcp_abort(pcb);
            goto aborted;
          }

          /* Notify application that data has been received. */
          TCP_EVENT_RECV(pcb, recv_data, ERR_OK, err);
          if (err == ERR_ABRT) {
#if TCP_QUEUE_OOSEQ && LWIP_WND_SCALE
            if (rest != NULL) {
              pbuf_free(rest);
            }
#endif /* TCP_QUEUE_OOSEQ && LWIP_WND_SCALE */
            goto aborted;
          }

          /* If the upper layer can't receive this data, store it */
          if (err != ERR_OK) {
#if TCP_QUEUE_OOSEQ && LWIP_WND_SCALE
            if (rest != NULL) {
              pbuf_cat(recv_data, rest);
            }
#endif /* TCP_QUEUE_OOSEQ && LWIP_WND_SCALE */
            pcb->refused_data = recv_data;
            
#if TCP_QUEUE_OOSEQ && LWIP_WND_SCALE
            break;
          } else {
            /* Upper layer received the data, go on with the rest if > 64K */
            recv_data = rest;
#endif /* TCP_QUEUE_OOSEQ && LWIP_WND_SCALE */
          }
        }

        /* If a FIN segment was received, we call the callback
           function with a NULL buffer to indicate EOF. */
        if (recv_flags & TF_GOT_FIN) {
          if (pcb->refused_data != NULL) {
            /* Delay this if we have refused data. */
            pcb->refused_data->flags |= PBUF_FLAG_TCP_FIN;
          } else {
            /* correct rcv_wnd as the application won't call tcp_recved()
               for the FIN's seqno */
            if (pcb->rcv_wnd != TCP_WND_MAX(pcb)) {
              pcb->rcv_wnd++;
            }
            TCP_EVENT_CLOSED(pcb, err);
            if (err == ERR_ABRT) {
              goto aborted;
            }
          }
        }

        tcp_input_pcb = NULL;
        if (tcp_input_delayed_close(pcb)) {
          goto aborted;
        }
        /* Try to send something out. */
        tcp_output(pcb);
#if TCP_INPUT_DEBUG
#if TCP_DEBUG
        tcp_debug_print_state(pcb->state);
#endif /* TCP_DEBUG */
#endif /* TCP_INPUT_DEBUG */
      }
    }
    /* Jump target if pcb has been aborted in a callback (by calling tcp_abort()).
       Below this line, 'pcb' may not be dereferenced! */
aborted:
    tcp_input_pcb = NULL;
    recv_data = NULL;

    /* give up our reference to inseg.p */
    if (inseg.p != NULL) {
      pbuf_free(inseg.p);
      inseg.p = NULL;
    }
  } else {
    /* If no matching PCB was found, send a TCP RST (reset) to the
       sender. */
    if (!(TCPH_FLAGS(tcphdr) & TCP_RST)) {
      TCP_STATS_INC(tcp.proterr);
      TCP_STATS_INC(tcp.drop);
      tcp_rst(NULL, ackno, seqno + tcplen, ip_current_dest_addr(),
              ip_current_src_addr(), tcphdr->dest, tcphdr->src);
    }
    pbuf_free(p);
  }

  PERF_STOP("tcp_input");
  return;
dropped:
  TCP_STATS_INC(tcp.drop);
  MIB2_STATS_INC(mib2.tcpinerrs);
  pbuf_free(p);
}
```

## 14、UDP协议

### 1）简介

- 特点
  - 无连接、不可靠
  - 速度极快，实时性好
  - 出现错误直接丢弃，无反馈
  - 支持一对一、一对多、多对一、多对多的交互通信
- 常用端口
  - 53：DNS
  - 69：TFTP
  - 123：NTP
  - 161：SNMP

### 2）UDP报文结构

![image-20200316120547043](images\LwIP\UDP报文封装)

![image-20200316120621571](D:\Book\StudyNote\images\LwIP\UDP报文结构.png)

```C++
PACK_STRUCT_BEGIN
struct udp_hdr {
  PACK_STRUCT_FIELD(u16_t src);
  PACK_STRUCT_FIELD(u16_t dest);  /* src/dest UDP ports */
  PACK_STRUCT_FIELD(u16_t len);
  PACK_STRUCT_FIELD(u16_t chksum);
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END
```



### 3）PCB

```C++
/** the UDP protocol control block */
struct udp_pcb {
/** Common members of all PCB types */
  IP_PCB;

/* Protocol specific PCB members */

  struct udp_pcb *next;

  u8_t flags;
  /** ports are in host byte order */
  u16_t local_port, remote_port;

#if LWIP_MULTICAST_TX_OPTIONS
#if LWIP_IPV4
  /** outgoing network interface for multicast packets, by IPv4 address (if not 'any') */
  ip4_addr_t mcast_ip4;
#endif /* LWIP_IPV4 */
  /** outgoing network interface for multicast packets, by interface index (if nonzero) */
  u8_t mcast_ifindex;
  /** TTL for outgoing multicast packets */
  u8_t mcast_ttl;
#endif /* LWIP_MULTICAST_TX_OPTIONS */

#if LWIP_UDPLITE
  /** used for UDP_LITE only */
  u16_t chksum_len_rx, chksum_len_tx;
#endif /* LWIP_UDPLITE */

  /** receive callback function */
  udp_recv_fn recv;
  /** user-supplied argument for the recv callback */
  void *recv_arg;
};
```

### 4）发送

```C++
err_t
udp_send(struct udp_pcb *pcb, struct pbuf *p)
{
  if (IP_IS_ANY_TYPE_VAL(pcb->remote_ip)) {
    return ERR_VAL;
  }

  /* send to the packet using remote ip and port stored in the pcb */
  return udp_sendto(pcb, p, &pcb->remote_ip, pcb->remote_port);
}

err_t
udp_sendto(struct udp_pcb *pcb, struct pbuf *p,
           const ip_addr_t *dst_ip, u16_t dst_port)
{
#if LWIP_CHECKSUM_ON_COPY && CHECKSUM_GEN_UDP
  return udp_sendto_chksum(pcb, p, dst_ip, dst_port, 0, 0);
}

/** @ingroup udp_raw
 * Same as udp_sendto(), but with checksum */
err_t
udp_sendto_chksum(struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *dst_ip,
                  u16_t dst_port, u8_t have_chksum, u16_t chksum)
{
#endif /* LWIP_CHECKSUM_ON_COPY && CHECKSUM_GEN_UDP */
  struct netif *netif;

  if (!IP_ADDR_PCB_VERSION_MATCH(pcb, dst_ip)) {
    return ERR_VAL;
  }

  if (pcb->netif_idx != NETIF_NO_INDEX) {
    netif = netif_get_by_index(pcb->netif_idx);
  } else {
#if LWIP_MULTICAST_TX_OPTIONS
    netif = NULL;
    if (ip_addr_ismulticast(dst_ip)) {
      /* For IPv6, the interface to use for packets with a multicast destination
       * is specified using an interface index. The same approach may be used for
       * IPv4 as well, in which case it overrides the IPv4 multicast override
       * address below. Here we have to look up the netif by going through the
       * list, but by doing so we skip a route lookup. If the interface index has
       * gone stale, we fall through and do the regular route lookup after all. */
      if (pcb->mcast_ifindex != NETIF_NO_INDEX) {
        netif = netif_get_by_index(pcb->mcast_ifindex);
      }
      else
        {
          /* IPv4 does not use source-based routing by default, so we use an
             administratively selected interface for multicast by default.
             However, this can be overridden by setting an interface address
             in pcb->mcast_ip4 that is used for routing. If this routing lookup
             fails, we try regular routing as though no override was set. */
          if (!ip4_addr_isany_val(pcb->mcast_ip4) &&
              !ip4_addr_cmp(&pcb->mcast_ip4, IP4_ADDR_BROADCAST)) {
            netif = ip4_route_src(ip_2_ip4(&pcb->local_ip), &pcb->mcast_ip4);
          }
        }
    }

    if (netif == NULL)
#endif /* LWIP_MULTICAST_TX_OPTIONS */
    {
      /* find the outgoing network interface for this packet */
      netif = ip_route(&pcb->local_ip, dst_ip);
    }
  }

  /* no outgoing network interface could be found? */
  if (netif == NULL) {
    UDP_STATS_INC(udp.rterr);
    return ERR_RTE;
  }
#if LWIP_CHECKSUM_ON_COPY && CHECKSUM_GEN_UDP
  return udp_sendto_if_chksum(pcb, p, dst_ip, dst_port, netif, have_chksum, chksum);
#else /* LWIP_CHECKSUM_ON_COPY && CHECKSUM_GEN_UDP */
  return udp_sendto_if(pcb, p, dst_ip, dst_port, netif);
#endif /* LWIP_CHECKSUM_ON_COPY && CHECKSUM_GEN_UDP */
}

err_t
udp_sendto_if(struct udp_pcb *pcb, struct pbuf *p,
              const ip_addr_t *dst_ip, u16_t dst_port, struct netif *netif)
{
#if LWIP_CHECKSUM_ON_COPY && CHECKSUM_GEN_UDP
  return udp_sendto_if_chksum(pcb, p, dst_ip, dst_port, netif, 0, 0);
}

/** Same as udp_sendto_if(), but with checksum */
err_t
udp_sendto_if_chksum(struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *dst_ip,
                     u16_t dst_port, struct netif *netif, u8_t have_chksum,
                     u16_t chksum)
{
#endif /* LWIP_CHECKSUM_ON_COPY && CHECKSUM_GEN_UDP */
  const ip_addr_t *src_ip;

  if (!IP_ADDR_PCB_VERSION_MATCH(pcb, dst_ip)) {
    return ERR_VAL;
  }

  /* PCB local address is IP_ANY_ADDR or multicast? */
    if (ip4_addr_isany(ip_2_ip4(&pcb->local_ip)) ||
        ip4_addr_ismulticast(ip_2_ip4(&pcb->local_ip))) {
      /* if the local_ip is any or multicast
       * use the outgoing network interface IP address as source address */
      src_ip = netif_ip_addr4(netif);
    } else {
      /* check if UDP PCB local IP address is correct
       * this could be an old address if netif->ip_addr has changed */
      if (!ip4_addr_cmp(ip_2_ip4(&(pcb->local_ip)), netif_ip4_addr(netif))) {
        /* local_ip doesn't match, drop the packet */
        return ERR_RTE;
      }
      /* use UDP PCB local IP address as source address */
      src_ip = &pcb->local_ip;
    }
#if LWIP_CHECKSUM_ON_COPY && CHECKSUM_GEN_UDP
  return udp_sendto_if_src_chksum(pcb, p, dst_ip, dst_port, netif, have_chksum, chksum, src_ip);
#else /* LWIP_CHECKSUM_ON_COPY && CHECKSUM_GEN_UDP */
  return udp_sendto_if_src(pcb, p, dst_ip, dst_port, netif, src_ip);
#endif /* LWIP_CHECKSUM_ON_COPY && CHECKSUM_GEN_UDP */
}

udp_sendto_if_src(struct udp_pcb *pcb, struct pbuf *p,
                  const ip_addr_t *dst_ip, u16_t dst_port, struct netif *netif, const ip_addr_t *src_ip)
{
#if LWIP_CHECKSUM_ON_COPY && CHECKSUM_GEN_UDP
  return udp_sendto_if_src_chksum(pcb, p, dst_ip, dst_port, netif, 0, 0, src_ip);
}

/** Same as udp_sendto_if_src(), but with checksum */
err_t
udp_sendto_if_src_chksum(struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *dst_ip,
                         u16_t dst_port, struct netif *netif, u8_t have_chksum,
                         u16_t chksum, const ip_addr_t *src_ip)
{
#endif /* LWIP_CHECKSUM_ON_COPY && CHECKSUM_GEN_UDP */
  struct udp_hdr *udphdr;
  err_t err;
  struct pbuf *q; /* q will be sent down the stack */
  u8_t ip_proto;
  u8_t ttl;

  LWIP_ASSERT_CORE_LOCKED();

  if (!IP_ADDR_PCB_VERSION_MATCH(pcb, src_ip) ||
      !IP_ADDR_PCB_VERSION_MATCH(pcb, dst_ip)) {
    return ERR_VAL;
  }

#if LWIP_IPV4 && IP_SOF_BROADCAST
  /* broadcast filter? */
  if (!ip_get_option(pcb, SOF_BROADCAST) &&
      ip_addr_isbroadcast(dst_ip, netif)) {
    return ERR_VAL;
  }
#endif /* LWIP_IPV4 && IP_SOF_BROADCAST */

  /* if the PCB is not yet bound to a port, bind it here */
  if (pcb->local_port == 0) {
    err = udp_bind(pcb, &pcb->local_ip, pcb->local_port);
    if (err != ERR_OK) {
      return err;
    }
  }

  /* packet too large to add a UDP header without causing an overflow? */
  if ((u16_t)(p->tot_len + UDP_HLEN) < p->tot_len) {
    return ERR_MEM;
  }
  /* not enough space to add an UDP header to first pbuf in given p chain? */
  if (pbuf_add_header(p, UDP_HLEN)) {
    /* allocate header in a separate new pbuf */
    q = pbuf_alloc(PBUF_IP, UDP_HLEN, PBUF_RAM);
    /* new header pbuf could not be allocated? */
    if (q == NULL) {
      return ERR_MEM;
    }
    if (p->tot_len != 0) {
      /* chain header q in front of given pbuf p (only if p contains data) */
      pbuf_chain(q, p);
    }
    /* first pbuf q points to header pbuf */    
  } else {
    /* adding space for header within p succeeded */
    /* first pbuf q equals given pbuf */
    q = p;
  }
  /* q now represents the packet to be sent */
  udphdr = (struct udp_hdr *)q->payload;
  udphdr->src = lwip_htons(pcb->local_port);
  udphdr->dest = lwip_htons(dst_port);
  /* in UDP, 0 checksum means 'no checksum' */
  udphdr->chksum = 0x0000;

  /* Multicast Loop? */
#if LWIP_MULTICAST_TX_OPTIONS
  if (((pcb->flags & UDP_FLAGS_MULTICAST_LOOP) != 0) && ip_addr_ismulticast(dst_ip)) {
    q->flags |= PBUF_FLAG_MCASTLOOP;
  }
#endif /* LWIP_MULTICAST_TX_OPTIONS */
  
#if LWIP_UDPLITE
  /* UDP Lite protocol? */
  if (pcb->flags & UDP_FLAGS_UDPLITE) {
    u16_t chklen, chklen_hdr;
    /* set UDP message length in UDP header */
    chklen_hdr = chklen = pcb->chksum_len_tx;
    if ((chklen < sizeof(struct udp_hdr)) || (chklen > q->tot_len)) {
      if (chklen != 0) {
        
      }
      /* For UDP-Lite, checksum length of 0 means checksum
         over the complete packet. (See RFC 3828 chap. 3.1)
         At least the UDP-Lite header must be covered by the
         checksum, therefore, if chksum_len has an illegal
         value, we generate the checksum over the complete
         packet to be safe. */
      chklen_hdr = 0;
      chklen = q->tot_len;
    }
    udphdr->len = lwip_htons(chklen_hdr);
    /* calculate checksum */
#if CHECKSUM_GEN_UDP
    IF__NETIF_CHECKSUM_ENABLED(netif, NETIF_CHECKSUM_GEN_UDP) {
#if LWIP_CHECKSUM_ON_COPY
      if (have_chksum) {
        chklen = UDP_HLEN;
      }
#endif /* LWIP_CHECKSUM_ON_COPY */
      udphdr->chksum = ip_chksum_pseudo_partial(q, IP_PROTO_UDPLITE,
                       q->tot_len, chklen, src_ip, dst_ip);
#if LWIP_CHECKSUM_ON_COPY
      if (have_chksum) {
        u32_t acc;
        acc = udphdr->chksum + (u16_t)~(chksum);
        udphdr->chksum = FOLD_U32T(acc);
      }
#endif /* LWIP_CHECKSUM_ON_COPY */

      /* chksum zero must become 0xffff, as zero means 'no checksum' */
      if (udphdr->chksum == 0x0000) {
        udphdr->chksum = 0xffff;
      }
    }
#endif /* CHECKSUM_GEN_UDP */

    ip_proto = IP_PROTO_UDPLITE;
  } else
#endif /* LWIP_UDPLITE */
  {      /* UDP */
    udphdr->len = lwip_htons(q->tot_len);
    /* calculate checksum */
#if CHECKSUM_GEN_UDP
    IF__NETIF_CHECKSUM_ENABLED(netif, NETIF_CHECKSUM_GEN_UDP) {
      /* Checksum is mandatory over IPv6. */
      if (IP_IS_V6(dst_ip) || (pcb->flags & UDP_FLAGS_NOCHKSUM) == 0) {
        u16_t udpchksum;
#if LWIP_CHECKSUM_ON_COPY
        if (have_chksum) {
          u32_t acc;
          udpchksum = ip_chksum_pseudo_partial(q, IP_PROTO_UDP,
                                               q->tot_len, UDP_HLEN, src_ip, dst_ip);
          acc = udpchksum + (u16_t)~(chksum);
          udpchksum = FOLD_U32T(acc);
        } else
#endif /* LWIP_CHECKSUM_ON_COPY */
        {
          udpchksum = ip_chksum_pseudo(q, IP_PROTO_UDP, q->tot_len,
                                       src_ip, dst_ip);
        }

        /* chksum zero must become 0xffff, as zero means 'no checksum' */
        if (udpchksum == 0x0000) {
          udpchksum = 0xffff;
        }
        udphdr->chksum = udpchksum;
      }
    }
#endif /* CHECKSUM_GEN_UDP */
    ip_proto = IP_PROTO_UDP;
  }

  /* Determine TTL to use */
#if LWIP_MULTICAST_TX_OPTIONS
  ttl = (ip_addr_ismulticast(dst_ip) ? udp_get_multicast_ttl(pcb) : pcb->ttl);
#else /* LWIP_MULTICAST_TX_OPTIONS */
  ttl = pcb->ttl;
#endif /* LWIP_MULTICAST_TX_OPTIONS */

  /* output to IP */
  NETIF_SET_HINTS(netif, &(pcb->netif_hints));
  err = ip_output_if_src(q, src_ip, dst_ip, ttl, pcb->tos, ip_proto, netif);
  NETIF_RESET_HINTS(netif);

  /* @todo: must this be increased even if error occurred? */
  MIB2_STATS_INC(mib2.udpoutdatagrams);

  /* did we chain a separate header pbuf earlier? */
  if (q != p) {
    /* free the header pbuf */
    pbuf_free(q);
    q = NULL;
    /* p is still referenced by the caller, and will live on */
  }

  UDP_STATS_INC(udp.xmit);
  return err;
}
```

### 5）接收

```C++
void
udp_input(struct pbuf *p, struct netif *inp)
{
  struct udp_hdr *udphdr;
  struct udp_pcb *pcb, *prev;
  struct udp_pcb *uncon_pcb;
  u16_t src, dest;
  u8_t broadcast;
  u8_t for_us = 0;

  /* Check minimum length (UDP header) */
  if (p->len < UDP_HLEN) {
    /* drop short packets */
    UDP_STATS_INC(udp.lenerr);
    UDP_STATS_INC(udp.drop);
    MIB2_STATS_INC(mib2.udpinerrors);
    pbuf_free(p);
    goto end;
  }

  udphdr = (struct udp_hdr *)p->payload;

  /* is broadcast packet ? */
  broadcast = ip_addr_isbroadcast(ip_current_dest_addr(), ip_current_netif());

  /* convert src and dest ports to host byte order */
  src = lwip_ntohs(udphdr->src);
  dest = lwip_ntohs(udphdr->dest);

  udp_debug_print(udphdr);

  pcb = NULL;
  prev = NULL;
  uncon_pcb = NULL;
  /* Iterate through the UDP pcb list for a matching pcb.
   * 'Perfect match' pcbs (connected to the remote port & ip address) are
   * preferred. If no perfect match is found, the first unconnected pcb that
   * matches the local port and ip address gets the datagram. */
  for (pcb = udp_pcbs; pcb != NULL; pcb = pcb->next) {
    /* compare PCB local addr+port to UDP destination addr+port */
    if ((pcb->local_port == dest) &&
        (udp_input_local_match(pcb, inp, broadcast) != 0)) {
      if ((pcb->flags & UDP_FLAGS_CONNECTED) == 0) {
        if (uncon_pcb == NULL) {
          /* the first unconnected matching PCB */
          uncon_pcb = pcb;
#if LWIP_IPV4
        } else if (broadcast && ip4_current_dest_addr()->addr == IPADDR_BROADCAST) {
          /* global broadcast address (only valid for IPv4; match was checked before) */
          if (!IP_IS_V4_VAL(uncon_pcb->local_ip) || !ip4_addr_cmp(ip_2_ip4(&uncon_pcb->local_ip), netif_ip4_addr(inp))) {
            /* uncon_pcb does not match the input netif, check this pcb */
            if (IP_IS_V4_VAL(pcb->local_ip) && ip4_addr_cmp(ip_2_ip4(&pcb->local_ip), netif_ip4_addr(inp))) {
              /* better match */
              uncon_pcb = pcb;
            }
          }
#endif /* LWIP_IPV4 */
        }
#if SO_REUSE
        else if (!ip_addr_isany(&pcb->local_ip)) {
          /* prefer specific IPs over catch-all */
          uncon_pcb = pcb;
        }
#endif /* SO_REUSE */
      }

      /* compare PCB remote addr+port to UDP source addr+port */
      if ((pcb->remote_port == src) &&
          (ip_addr_isany_val(pcb->remote_ip) ||
           ip_addr_cmp(&pcb->remote_ip, ip_current_src_addr()))) {
        /* the first fully matching PCB */
        if (prev != NULL) {
          /* move the pcb to the front of udp_pcbs so that is
             found faster next time */
          prev->next = pcb->next;
          pcb->next = udp_pcbs;
          udp_pcbs = pcb;
        } else {
          UDP_STATS_INC(udp.cachehit);
        }
        break;
      }
    }

    prev = pcb;
  }
  /* no fully matching pcb found? then look for an unconnected pcb */
  if (pcb == NULL) {
    pcb = uncon_pcb;
  }

  /* Check checksum if this is a match or if it was directed at us. */
  if (pcb != NULL) {
    for_us = 1;
  } else {
#if LWIP_IPV6
    if (ip_current_is_v6()) {
      for_us = netif_get_ip6_addr_match(inp, ip6_current_dest_addr()) >= 0;
    }
#endif /* LWIP_IPV6 */
#if LWIP_IPV4
    if (!ip_current_is_v6()) {
      for_us = ip4_addr_cmp(netif_ip4_addr(inp), ip4_current_dest_addr());
    }
#endif /* LWIP_IPV4 */
  }

  if (for_us) {    
#if CHECKSUM_CHECK_UDP
    IF__NETIF_CHECKSUM_ENABLED(inp, NETIF_CHECKSUM_CHECK_UDP) {
#if LWIP_UDPLITE
      if (ip_current_header_proto() == IP_PROTO_UDPLITE) {
        /* Do the UDP Lite checksum */
        u16_t chklen = lwip_ntohs(udphdr->len);
        if (chklen < sizeof(struct udp_hdr)) {
          if (chklen == 0) {
            /* For UDP-Lite, checksum length of 0 means checksum
               over the complete packet (See RFC 3828 chap. 3.1) */
            chklen = p->tot_len;
          } else {
            /* At least the UDP-Lite header must be covered by the
               checksum! (Again, see RFC 3828 chap. 3.1) */
            goto chkerr;
          }
        }
        if (ip_chksum_pseudo_partial(p, IP_PROTO_UDPLITE,
                                     p->tot_len, chklen,
                                     ip_current_src_addr(), ip_current_dest_addr()) != 0) {
          goto chkerr;
        }
      } else
#endif /* LWIP_UDPLITE */
      {
        if (udphdr->chksum != 0) {
          if (ip_chksum_pseudo(p, IP_PROTO_UDP, p->tot_len,
                               ip_current_src_addr(),
                               ip_current_dest_addr()) != 0) {
            goto chkerr;
          }
        }
      }
    }
#endif /* CHECKSUM_CHECK_UDP */
    if (pbuf_remove_header(p, UDP_HLEN)) {
      /* Can we cope with this failing? Just assert for now */
      UDP_STATS_INC(udp.drop);
      MIB2_STATS_INC(mib2.udpinerrors);
      pbuf_free(p);
      goto end;
    }

    if (pcb != NULL) {
      MIB2_STATS_INC(mib2.udpindatagrams);
#if SO_REUSE && SO_REUSE_RXTOALL
      if (ip_get_option(pcb, SOF_REUSEADDR) &&
          (broadcast || ip_addr_ismulticast(ip_current_dest_addr()))) {
        /* pass broadcast- or multicast packets to all multicast pcbs
           if SOF_REUSEADDR is set on the first match */
        struct udp_pcb *mpcb;
        for (mpcb = udp_pcbs; mpcb != NULL; mpcb = mpcb->next) {
          if (mpcb != pcb) {
            /* compare PCB local addr+port to UDP destination addr+port */
            if ((mpcb->local_port == dest) &&
                (udp_input_local_match(mpcb, inp, broadcast) != 0)) {
              /* pass a copy of the packet to all local matches */
              if (mpcb->recv != NULL) {
                struct pbuf *q;
                q = pbuf_clone(PBUF_RAW, PBUF_POOL, p);
                if (q != NULL) {
                  mpcb->recv(mpcb->recv_arg, mpcb, q, ip_current_src_addr(), src);
                }
              }
            }
          }
        }
      }
#endif /* SO_REUSE && SO_REUSE_RXTOALL */
      /* callback */
      if (pcb->recv != NULL) {
        /* now the recv function is responsible for freeing p */
        pcb->recv(pcb->recv_arg, pcb, p, ip_current_src_addr(), src);
      } else {
        /* no recv function registered? then we have to free the pbuf! */
        pbuf_free(p);
        goto end;
      }
    } else {
  
#if LWIP_ICMP || LWIP_ICMP6
      /* No match was found, send ICMP destination port unreachable unless
         destination address was broadcast/multicast. */
      if (!broadcast && !ip_addr_ismulticast(ip_current_dest_addr())) {
        /* move payload pointer back to ip header */
        pbuf_header_force(p, (s16_t)(ip_current_header_tot_len() + UDP_HLEN));
        icmp_port_unreach(ip_current_is_v6(), p);
      }
#endif /* LWIP_ICMP || LWIP_ICMP6 */
      UDP_STATS_INC(udp.proterr);
      UDP_STATS_INC(udp.drop);
      MIB2_STATS_INC(mib2.udpnoports);
      pbuf_free(p);
    }
  } else {
    pbuf_free(p);
  }
end:
  PERF_STOP("udp_input");
  return;
#if CHECKSUM_CHECK_UDP
chkerr:
  UDP_STATS_INC(udp.chkerr);
  UDP_STATS_INC(udp.drop);
  MIB2_STATS_INC(mib2.udpinerrors);
  pbuf_free(p);
  PERF_STOP("udp_input");
#endif /* CHECKSUM_CHECK_UDP */
}
```

## 15、使用NetConn接口编程

### 1）简介

- pbuf是对用户透明的
- 用户端的网络数据基于netbuf进行封装
- lwipopts.h启用 `#define LWIP_NETCONN 1  `

### 2）netbuf结构体

```C++
struct netbuf {
  struct pbuf *p, *ptr;
  ip_addr_t addr;
  u16_t port;
#if LWIP_NETBUF_RECVINFO || LWIP_CHECKSUM_ON_COPY
  u8_t flags;
  u16_t toport_chksum;
#if LWIP_NETBUF_RECVINFO
  ip_addr_t toaddr;
#endif /* LWIP_NETBUF_RECVINFO */
#endif /* LWIP_NETBUF_RECVINFO || LWIP_CHECKSUM_ON_COPY */
};
```

- addr：数据发送方的ip地址
- port：数据发送方的端口号
- p：指向pbuf链表
- ptr：指向pbuf，由netbuf_next、netbuf_first函数控制

### 3）netbuf相关函数说明

- netbuf_new：申请新的netbuf结构体内存空间

  ```C++
  struct netbuf *netbuf_new(void)
  {
    struct netbuf *buf;
  
    buf = (struct netbuf *)memp_malloc(MEMP_NETBUF);
    if (buf != NULL) {
      memset(buf, 0, sizeof(struct netbuf));
    }
    return buf;
  }
  ```

- netbuf_delete：释放netbuf结构体内存空间

  ```C++
  void netbuf_delete(struct netbuf *buf)
  {
    if (buf != NULL) {
      if (buf->p != NULL) {
        pbuf_free(buf->p);
        buf->p = buf->ptr = NULL;
      }
      memp_free(MEMP_NETBUF, buf);
    }
  }    
  ```

- netbuf_alloc：为p字段分配指定大小的内存空间

  ```C++
  void * netbuf_alloc(struct netbuf *buf, u16_t size)
  {
    /* Deallocate any previously allocated memory. */
    if (buf->p != NULL) {
      pbuf_free(buf->p);
    }
    buf->p = pbuf_alloc(PBUF_TRANSPORT, size, PBUF_RAM);
    if (buf->p == NULL) {
      return NULL;
    }
    buf->ptr = buf->p;
    return buf->p->payload;
  }
  ```

- netbuf_free：释放p指向的内存空间

  ```C++
  void netbuf_free(struct netbuf *buf)
  {
    LWIP_ERROR("netbuf_free: invalid buf", (buf != NULL), return;);
    if (buf->p != NULL) {
      pbuf_free(buf->p);
    }
    buf->p = buf->ptr = NULL;
  #if LWIP_CHECKSUM_ON_COPY
    buf->flags = 0;
    buf->toport_chksum = 0;
  #endif /* LWIP_CHECKSUM_ON_COPY */
  }
  ```

- netbuf_ref：静态数据初始化

  ```C++
  err_t netbuf_ref(struct netbuf *buf, const void *dataptr, u16_t size)
  {
    if (buf->p != NULL) {
      pbuf_free(buf->p);
    }
    buf->p = pbuf_alloc(PBUF_TRANSPORT, 0, PBUF_REF);
    if (buf->p == NULL) {
      buf->ptr = NULL;
      return ERR_MEM;
    }
    ((struct pbuf_rom *)buf->p)->payload = dataptr;
    buf->p->len = buf->p->tot_len = size;
    buf->ptr = buf->p;
    return ERR_OK;
  }
  ```

- netbuf_chain：合成链表

  ```C++
  void netbuf_chain(struct netbuf *head, struct netbuf *tail)
  {
    pbuf_cat(head->p, tail->p);
    head->ptr = head->p;
    memp_free(MEMP_NETBUF, tail);
  }
  ```

- netbuf_data：获取数据

  ```C++
  err_t netbuf_data(struct netbuf *buf, void **dataptr, u16_t *len)
  {
    if (buf->ptr == NULL) {
      return ERR_BUF;
    }
    *dataptr = buf->ptr->payload;
    *len = buf->ptr->len;
    return ERR_OK;
  }
  ```

- netbuf_next、netbuf_first：移动ptr指针

  ```C++
  s8_t
  netbuf_next(struct netbuf *buf)
  {
    if (buf->ptr->next == NULL) {
      return -1;
    }
    buf->ptr = buf->ptr->next;
    if (buf->ptr->next == NULL) {
      return 1;
    }
    return 0;
  }
  
  /**
   * @ingroup netbuf
   * Move the current data pointer of a packet buffer contained in a netbuf
   * to the beginning of the packet.
   * The packet buffer itself is not modified.
   *
   * @param buf the netbuf to modify
   */
  void
  netbuf_first(struct netbuf *buf)
  {
    buf->ptr = buf->p;
  }
  ```
  
- 其他

  ```C++
  #define netbuf_copy_partial(buf, dataptr, len, offset) \
    pbuf_copy_partial((buf)->p, (dataptr), (len), (offset))
  #define netbuf_copy(buf,dataptr,len) netbuf_copy_partial(buf, dataptr, len, 0)
  #define netbuf_take(buf, dataptr, len) pbuf_take((buf)->p, dataptr, len)
  #define netbuf_len(buf)              ((buf)->p->tot_len)
  #define netbuf_fromaddr(buf)         (&((buf)->addr))
  #define netbuf_set_fromaddr(buf, fromaddr) ip_addr_set(&((buf)->addr), fromaddr)
  #define netbuf_fromport(buf)         ((buf)->port)
  #if LWIP_NETBUF_RECVINFO
  #define netbuf_destaddr(buf)         (&((buf)->toaddr))
  #define netbuf_set_destaddr(buf, destaddr) ip_addr_set(&((buf)->toaddr), destaddr)
  #if LWIP_CHECKSUM_ON_COPY
  #define netbuf_destport(buf)         (((buf)->flags & NETBUF_FLAG_DESTADDR) ? (buf)->toport_chksum : 0)
  #else /* LWIP_CHECKSUM_ON_COPY */
  #define netbuf_destport(buf)         ((buf)->toport_chksum)
  #endif /* LWIP_CHECKSUM_ON_COPY */
  #endif /* LWIP_NETBUF_RECVINFO */
  #if LWIP_CHECKSUM_ON_COPY
  #define netbuf_set_chksum(buf, chksum) do { (buf)->flags = NETBUF_FLAG_CHKSUM; \
                                              (buf)->toport_chksum = chksum; } while(0)
  ```

### 4）netconn结构体

  用于描述一个TCP或UDP连接

```C++
struct netconn {
  /** type of the netconn (TCP, UDP or RAW) */
  enum netconn_type type;
  /** current state of the netconn */
  enum netconn_state state;
  /** the lwIP internal protocol control block */
  union {
    struct ip_pcb  *ip;
    struct tcp_pcb *tcp;
    struct udp_pcb *udp;
    struct raw_pcb *raw;
  } pcb;
  /** the last asynchronous unreported error this netconn had */
  err_t pending_err;
#if !LWIP_NETCONN_SEM_PER_THREAD
  /** sem that is used to synchronously execute functions in the core context */
  sys_sem_t op_completed;
#endif
  /** mbox where received packets are stored until they are fetched
      by the netconn application thread (can grow quite big) */
  sys_mbox_t recvmbox;
#if LWIP_TCP
  /** mbox where new connections are stored until processed
      by the application thread */
  sys_mbox_t acceptmbox;
#endif /* LWIP_TCP */
#if LWIP_NETCONN_FULLDUPLEX
  /** number of threads waiting on an mbox. This is required to unblock
      all threads when closing while threads are waiting. */
  int mbox_threads_waiting;
#endif
  /** only used for socket layer */
#if LWIP_SOCKET
  int socket;
#endif /* LWIP_SOCKET */
#if LWIP_SO_SNDTIMEO
  /** timeout to wait for sending data (which means enqueueing data for sending
      in internal buffers) in milliseconds */
  s32_t send_timeout;
#endif /* LWIP_SO_RCVTIMEO */
#if LWIP_SO_RCVTIMEO
  /** timeout in milliseconds to wait for new data to be received
      (or connections to arrive for listening netconns) */
  u32_t recv_timeout;
#endif /* LWIP_SO_RCVTIMEO */
#if LWIP_SO_RCVBUF
  /** maximum amount of bytes queued in recvmbox
      not used for TCP: adjust TCP_WND instead! */
  int recv_bufsize;
  /** number of bytes currently in recvmbox to be received,
      tested against recv_bufsize to limit bytes on recvmbox
      for UDP and RAW, used for FIONREAD */
  int recv_avail;
#endif /* LWIP_SO_RCVBUF */
#if LWIP_SO_LINGER
   /** values <0 mean linger is disabled, values > 0 are seconds to linger */
  s16_t linger;
#endif /* LWIP_SO_LINGER */
  /** flags holding more netconn-internal state, see NETCONN_FLAG_* defines */
  u8_t flags;
#if LWIP_TCP
  /** TCP: when data passed to netconn_write doesn't fit into the send buffer,
      this temporarily stores the message.
      Also used during connect and close. */
  struct api_msg *current_msg;
#endif /* LWIP_TCP */
  /** A callback function that is informed about events for this netconn */
  netconn_callback callback;
};
```

### 5）netconn函数接口

- netconn_new

  ```C++
  enum netconn_type {
    NETCONN_INVALID     = 0,
    /** TCP IPv4 */
    NETCONN_TCP         = 0x10,
    /** UDP IPv4 */
    NETCONN_UDP         = 0x20,
    /** UDP IPv4 lite */
    NETCONN_UDPLITE     = 0x21,
    /** UDP IPv4 no checksum */
    NETCONN_UDPNOCHKSUM = 0x22,
      
    /** Raw connection IPv4 */
    NETCONN_RAW         = 0x40
  };
  
  struct netconn* netconn_new_with_proto_and_callback(enum netconn_type t, u8_t proto, netconn_callback callback);
  
  #define 	netconn_new(t)   netconn_new_with_proto_and_callback(t, 0, NULL)
  ```

- netconn_delete

  ```C++
  err_t   netconn_delete(struct netconn *conn);
  ```

- 常用函数

  ```C++
  err_t netconn_getaddr(struct netconn *conn, ip_addr_t *addr, u16_t *port, u8_t local);
  
  //TCP/UDP/RAW
  err_t netconn_bind(struct netconn *conn, const ip_addr_t *addr, u16_t port);
  
  //TCP/UDP/RAW
  err_t netconn_connect(struct netconn *conn, const ip_addr_t *addr, u16_t port);
  
  //UDP
  err_t netconn_disconnect(struct netconn *conn);
  
  //TCP
  #define TCP_DEFAULT_LISTEN_BACKLOG      0xff
  err_t netconn_listen_with_backlog(struct netconn *conn, u8_t backlog);
  
  //TCP
  #define netconn_listen(conn) netconn_listen_with_backlog(conn, TCP_DEFAULT_LISTEN_BACKLOG)
  
  //TCP
  err_t netconn_accept(struct netconn *conn, struct netconn **new_conn);
  
  //UDP/RAW
  err_t netconn_send(struct netconn *conn, struct netbuf *buf);
  
  //UDP/RAW
  err_t netconn_sendto(struct netconn *conn, struct netbuf *buf, const ip_addr_t *addr, u16_t port);
  
  //TCP/UDP/RAW
  err_t netconn_recv(struct netconn *conn, struct netbuf **new_buf);
  
  //TCP
  err_t netconn_write_partly(struct netconn *conn, const void *dataptr, size_t size, u8_t apiflags, size_t *bytes_written);
  
  //TCP
  #define netconn_write(conn, dataptr, size, apiflags) \
            netconn_write_partly(conn, dataptr, size, apiflags, NULL)
  
  //TCP
  err_t   netconn_close(struct netconn *conn);
  
  //TCP
  err_t 	netconn_shutdown (struct netconn *conn, u8_t shut_rx, u8_t shut_tx);
  ```

### 6）TCP Client

```C++
#include "lwip/opt.h"

#include "lwip/sys.h"
#include "lwip/api.h"

static void tcp_client(void *thread_param)
{
    struct netconn *conn;
    int ret;
    ip4_addr_t ipaddr;

    uint8_t send_buf[] = "This is a TCP Client test...\n";

    while
    {
        conn = netconn_new(NETCONN_TCP);
        if (conn == NULL)
        {
            printf("create conn failed!\n");
            vTaskDelay(10);
            continue;
        }

        IP4_ADDR(&ipaddr, 192, 168, 0, 181);
        ret = netconn_connect(conn, &ipaddr, 5001);
        if (ret == -1)
        {
            printf("Connect failed!\n");
            netconn_close(conn);
            vTaskDelay(10);
            continue;
        }

        printf("Connect to iperf server successful!\n");

        while (1)
        {
            ret = netconn_write(conn, send_buf, sizeof(send_buf), 0);

            vTaskDelay(1000);
        }
    }
}

void client_init(void)
{
    sys_thread_new("tcp_client", tcp_client, NULL, 512, 4);
}
```

### 7）TCP Server

```C++
#include "lwip/opt.h"

#include "lwip/sys.h"
#include "lwip/api.h"
static void tcpecho_thread(void *arg)
{
    struct netconn *conn, *newconn;
    err_t err;
    LWIP_UNUSED_ARG(arg);

/* Create a new connection identifier. */
/* Bind connection to well known port number 7. */
#if LWIP_IPV6
    conn = netconn_new(NETCONN_TCP_IPV6);
    netconn_bind(conn, IP6_ADDR_ANY, 5001);
#else  /* LWIP_IPV6 */
    conn = netconn_new(NETCONN_TCP);
    netconn_bind(conn, IP_ADDR_ANY, 5001);
#endif /* LWIP_IPV6 */
    LWIP_ERROR("tcpecho: invalid conn", (conn != NULL), return;);

    /* Tell connection to go into listening mode. */
    netconn_listen(conn);
    while (1)
    {

        /* Grab new connection. */
        err = netconn_accept(conn, &newconn);
        /*printf("accepted new connection %p\n", newconn);*/
        /* Process the new connection. */
        if (err == ERR_OK)
        {
            struct netbuf *buf;
            void *data;
            u16_t len;

            while ((err = netconn_recv(newconn, &buf)) == ERR_OK)
            {
                /*printf("Recved\n");*/
                do
                {
                    netbuf_data(buf, &data, &len);
                    err = netconn_write(newconn, data, len, NETCONN_COPY);

                    if (err != ERR_OK)
                    {
                        printf("tcpecho: netconn_write: error \"%s\"\n",
                               lwip_strerr(err));
                    }
                } while (netbuf_next(buf) >= 0);
                netbuf_delete(buf);
            }
            /*printf("Got EOF, looping\n");*/
            /* Close connection and discard connection identifier. */
            netconn_close(newconn);
            netconn_delete(newconn);
        }
    }
}

void tcpecho_init(void)
{
    sys_thread_new("tcpecho_thread", tcpecho_thread, NULL, 512, 4);
}
```

### 8）UDP

```C++
#include "lwip/opt.h"

#include "lwip/api.h"
#include "lwip/sys.h"

static void
udpecho_thread(void *arg)
{
    struct netconn *conn;
    struct netbuf *buf;
    char buffer[4096];
    err_t err;
    LWIP_UNUSED_ARG(arg);

#if LWIP_IPV6
    conn = netconn_new(NETCONN_UDP_IPV6);
    netconn_bind(conn, IP6_ADDR_ANY, 5001);
#else  /* LWIP_IPV6 */
    conn = netconn_new(NETCONN_UDP);
    netconn_bind(conn, IP_ADDR_ANY, 5001);
#endif /* LWIP_IPV6 */
    LWIP_ERROR("udpecho: invalid conn", (conn != NULL), return;);

    while (1)
    {
        err = netconn_recv(conn, &buf);
        if (err == ERR_OK)
        {
            if (netbuf_copy(buf, buffer, sizeof(buffer)) != buf->p->tot_len)
            {
                LWIP_DEBUGF(LWIP_DBG_ON, ("netbuf_copy failed\n"));
            }
            else
            {
                buffer[buf->p->tot_len] = '\0';
                err = netconn_send(conn, buf);
                if (err != ERR_OK)
                {
                    LWIP_DEBUGF(LWIP_DBG_ON, ("netconn_send failed: %d\n", (int)err));
                }
                else
                {
                    LWIP_DEBUGF(LWIP_DBG_ON, ("got %s\n", buffer));
                }
            }
            netbuf_delete(buf);
        }
    }
}

void udpecho_init(void)
{
    sys_thread_new("udpecho_thread", udpecho_thread, NULL, 2048, 4);
}

```

## 16、使用Socket接口编程

### 1）简介

- 基于netconn的再次封装
- 最多提供MEMP_NUM_NETCONN个socket
- lwipopts.h启用 `#define LWIP_SOCKET 1  `

### 2）TCP Client

```C++
#include "client.h"

#include "lwip/opt.h"

#include "lwip/sys.h"
#include "lwip/api.h"

#include "lwip/sockets.h"

#define PORT 5001
#define IP_ADDR "192.168.0.181"

static void client(void *thread_param)
{
    int sock = -1;
    struct sockaddr_in client_addr;

    uint8_t send_buf[] = "This is a TCP Client test...\n";

    while (1)
    {
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0)
        {
            printf("Socket error\n");
            vTaskDelay(10);
            continue;
        }

        client_addr.sin_family = AF_INET;
        client_addr.sin_port = htons(PORT);
        client_addr.sin_addr.s_addr = inet_addr(IP_ADDR);
        memset(&(client_addr.sin_zero), 0, sizeof(client_addr.sin_zero));

        if (connect(sock,
                    (struct sockaddr *)&client_addr,
                    sizeof(struct sockaddr)) == -1)
        {
            printf("Connect failed!\n");
            closesocket(sock);
            vTaskDelay(10);
            continue;
        }

        printf("Connect to iperf server successful!\n");

        while (1)
        {
            if (write(sock, send_buf, sizeof(send_buf)) < 0)
                break;

            vTaskDelay(1000);
        }

        closesocket(sock);
    }
}

void client_init(void)
{
    sys_thread_new("client", client, NULL, 512, 4);
}
```

### 3）TCP Server

```C++
#include "lwip/opt.h"
#include "lwip/sockets.h"

#include "lwip/sys.h"
#include "lwip/api.h"

#define PORT 5001
#define RECV_DATA (1024)

static void
tcpecho_thread(void *arg)
{
    int sock = -1, connected;
    char *recv_data;
    struct sockaddr_in server_addr, client_addr;
    socklen_t sin_size;
    int recv_data_len;

    recv_data = (char *)pvPortMalloc(RECV_DATA);
    if (recv_data == NULL)
    {
        printf("No memory\n");
        goto __exit;
    }

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        printf("Socket error\n");
        goto __exit;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);
    memset(&(server_addr.sin_zero), 0, sizeof(server_addr.sin_zero));

    if (bind(sock, (struct sockaddr *)&server_addr, sizeof(struct sockaddr)) == -1)
    {
        printf("Unable to bind\n");
        goto __exit;
    }

    if (listen(sock, 5) == -1)
    {
        printf("Listen error\n");
        goto __exit;
    }

    while (1)
    {
        sin_size = sizeof(struct sockaddr_in);

        connected = accept(sock, (struct sockaddr *)&client_addr, &sin_size);

        printf("new client connected from (%s, %d)\n",
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        {
            int flag = 1;

            setsockopt(connected,
                       IPPROTO_TCP,   /* set option at TCP level */
                       TCP_NODELAY,   /* name of option */
                       (void *)&flag, /* the cast is historical cruft */
                       sizeof(int));  /* length of option value */
        }

        while (1)
        {
            recv_data_len = recv(connected, recv_data, RECV_DATA, 0);

            if (recv_data_len <= 0)
                break;

            printf("recv %d len data\n", recv_data_len);

            write(connected, recv_data, recv_data_len);
        }
        if (connected >= 0)
            closesocket(connected);

        connected = -1;
    }
__exit:
    if (sock >= 0)
        closesocket(sock);
    if (recv_data)
        free(recv_data);
}

void tcpecho_init(void)
{
    sys_thread_new("tcpecho_thread", tcpecho_thread, NULL, 512, 4);
}
```

### 4）UDP

```C++
#include "udpecho.h"

#include "lwip/opt.h"

#include <lwip/sockets.h>
#include "lwip/api.h"
#include "lwip/sys.h"

#define PORT 5001
#define RECV_DATA (1024)

static void
udpecho_thread(void *arg)
{
    int sock = -1;
    char *recv_data;
    struct sockaddr_in udp_addr, seraddr;
    int recv_data_len;
    socklen_t addrlen;

    while (1)
    {
        recv_data = (char *)pvPortMalloc(RECV_DATA);
        if (recv_data == NULL)
        {
            printf("No memory\n");
            goto __exit;
        }

        sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0)
        {
            printf("Socket error\n");
            goto __exit;
        }

        udp_addr.sin_family = AF_INET;
        udp_addr.sin_addr.s_addr = INADDR_ANY;
        udp_addr.sin_port = htons(PORT);
        memset(&(udp_addr.sin_zero), 0, sizeof(udp_addr.sin_zero));

        if (bind(sock, (struct sockaddr *)&udp_addr, sizeof(struct sockaddr)) == -1)
        {
            printf("Unable to bind\n");
            goto __exit;
        }
        while (1)
        {
            recv_data_len = recvfrom(sock, recv_data,
                                     RECV_DATA, 0,
                                     (struct sockaddr *)&seraddr,
                                     &addrlen);

            /*显示发送端的 IP 地址*/
            printf("receive from %s\n", inet_ntoa(seraddr.sin_addr));

            /*显示发送端发来的字串*/
            printf("recevce:%s", recv_data);

            /*将字串返回给发送端*/
            sendto(sock, recv_data,
                   recv_data_len, 0,
                   (struct sockaddr *)&seraddr,
                   addrlen);
        }

    __exit:
        if (sock >= 0)
            closesocket(sock);
        if (recv_data)
            free(recv_data);
    }
}

void udpecho_init(void)
{
    sys_thread_new("udpecho_thread", udpecho_thread, NULL, 2048, 4);
}
```

## 17、使用RAW API接口编程

### 1）简介

- 基于回调的底层API接口
- RAW API的核心就是对控制块的处理

### 2）TCP Client

```C++
#include "tcpclient.h"
#include "lwip/netif.h"
#include "lwip/ip.h"
#include "lwip/tcp.h"
#include "lwip/init.h"
#include "netif/etharp.h"
#include "lwip/udp.h"
#include "lwip/pbuf.h"
#include <stdio.h>
#include <string.h>

static struct tcp_pcb *client_pcb = NULL;

static void client_err(void *arg, err_t err)
{
    printf("connect error! closed by core!!\n");
    printf("try to connect to server again!!\n");

    //连接失败的时候释放 TCP 控制块的内存
    tcp_close(client_pcb);

    //重新连接
    TCP_Client_Init();
}

static err_t client_send(void *arg, struct tcp_pcb *tpcb)
{
    uint8_t send_buf[] = "This is a TCP Client test...\n";

    tcp_write(tpcb, send_buf, sizeof(send_buf), 1);

    return ERR_OK;
}

static err_t client_recv(void *arg,
                         struct tcp_pcb *tpcb,
                         struct pbuf *p,
                         err_t err)
{
    if (p != NULL)
    {
        /* 更新窗口 */
        tcp_recved(tpcb, p->tot_len);

        /* 返回接收到的数据*/
        tcp_write(tpcb, p->payload, p->tot_len, 1);

        memset(p->payload, 0, p->tot_len);
        pbuf_free(p);
    }
    else if (err == ERR_OK)
    {
        //服务器断开连接
        printf("server has been disconnected!\n");
        tcp_close(tpcb);

        //重新连接
        TCP_Client_Init();
    }
    return ERR_OK;
}

static err_t client_connected(void *arg,
                              struct tcp_pcb *pcb,
                              err_t err)
{
    printf("connected ok!\n");

    //注册一个周期性回调函数
    tcp_poll(pcb, client_send, 2);

    //注册一个接收函数
    tcp_recv(pcb, client_recv);

    return ERR_OK;
}

void TCP_Client_Init(void)
{
    ip4_addr_t server_ip;
    /* 创建一个 TCP 控制块 */
    client_pcb = tcp_new();

    IP4_ADDR(&server_ip, 192, 168, 0, 181);

    printf("client start connect!\n");

    //开始连接
    tcp_connect(client_pcb,
                &server_ip,
                TCP_CLIENT_PORT,
                client_connected);

    tcp_err(client_pcb, client_err);
}
```

### 3）TCP Server

```C++
#include "tcpecho.h"
#include "lwip/netif.h"
#include "lwip/ip.h"
#include "lwip/tcp.h"
#include "lwip/init.h"
#include "netif/etharp.h"
#include "lwip/udp.h"
#include "lwip/pbuf.h"
#include <stdio.h>
#include <string.h>

static err_t tcpecho_recv(void *arg,
                          struct tcp_pcb *tpcb,
                          struct pbuf *p,
                          err_t err)
{
    if (p != NULL)
    {
        /* 更新窗口*/
        tcp_recved(tpcb, p->tot_len);

        /* 返回接收到的数据*/
        tcp_write(tpcb, p->payload, p->tot_len, 1);

        memset(p->payload, 0, p->tot_len);
        pbuf_free(p);
    }
    else if (err == ERR_OK)
    {
        return tcp_close(tpcb);
    }
    return ERR_OK;
}

static err_t tcpecho_accept(void *arg,
                            struct tcp_pcb *newpcb,
                            err_t err)
{

    tcp_recv(newpcb, tcpecho_recv);
    return ERR_OK;
}

void TCP_Echo_Init(void)
{
    struct tcp_pcb *pcb = NULL;

    /* 创建一个 TCP 控制块 */
    pcb = tcp_new();

    /* 绑定 TCP 控制块 */
    tcp_bind(pcb, IP_ADDR_ANY, TCP_ECHO_PORT);

    /* 进入监听状态 */
    pcb = tcp_listen(pcb);

    /* 处理连接 */
    tcp_accept(pcb, tcpecho_accept);
}
```

### 4）UDP

```C++
#include "lwip/netif.h"
#include "lwip/ip.h"
#include "lwip/tcp.h"
#include "lwip/init.h"
#include "netif/etharp.h"
#include "lwip/udp.h"
#include "lwip/pbuf.h"
#include <stdio.h>

static void udp_demo_callback(void *arg,
                              struct udp_pcb *upcb,
                              struct pbuf *p,
                              const ip_addr_t *addr,
                              u16_t port)
{
    struct pbuf *q = NULL;
    const char *reply = "This is reply!\n";

    if (arg)
    {
        printf("%s", (char *)arg);
    }

    pbuf_free(p);

    q = pbuf_alloc(PBUF_TRANSPORT, strlen(reply) + 1, PBUF_RAM);
    if (!q)
    {
        printf("out of PBUF_RAM\n");
        return;
    }

    memset(q->payload, 0, q->len);
    memcpy(q->payload, reply, strlen(reply));
    udp_sendto(upcb, q, addr, port);
    pbuf_free(q);
}

static char *st_buffer = "We get a data\n";
void UDP_Echo_Init(void)
{
    struct udp_pcb *udpecho_pcb;
    /* 新建一个控制块*/
    udpecho_pcb = udp_new();

    /* 绑定端口号 */
    udp_bind(udpecho_pcb, IP_ADDR_ANY, UDP_ECHO_PORT);

    /* 注册接收数据回调函数 */
    udp_recv(udpecho_pcb, udp_demo_callback, (void *)st_buffer);
}
```



