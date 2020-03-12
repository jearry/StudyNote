# LwIP应用开发实战

## 1、网络协议简介

略

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

    - 前导字段：7个0x55
    - 帧起始界定符：0xD5
    - 类型/长度：大于0x600为类型
    - 数据：0-1500长度
    - 填充：MAC数据包最低长度为64字节，数据少于46字节时，自动填充无效数据
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
    void ethernetif_input(void *pParams);
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

- pbuf_header，调整pbuf的payload指针，len和tot_len都会随之更新

  ```C++
  u8_t pbuf_header(struct pbuf *p, s16_t header_size_increment)
  ```

- pbuf_take，向pbuf的payload复制数据

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

### 1）将LwIP添加到裸机工程

### 2）移植头文件

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

