# Kubernetes实战

![Kubernetes实战](/Users/jearry/StudyNote/images/Kubernetes实战.jpg)

## 一、Kubernetes介绍

### 1、Kubernetes是什么

- Kubernetes是Google开源的容器集群管理系统。
- 构建在Docker技术之上，为容器化应用提供资源调度、部署运行、服务发现、扩容所容等一整套功能。
- 基于容器技术的Micro-PaaS平台
- 使应用程序能够以简单快捷的方式发布和更新，而无需停机

### 2、Kubernetes核心概念

- Pod
  - Pod是若干相关容器的组合
  - 这些容器运行在同一台宿主机上
  - 这些容器使用相同的网络命名空间、IP地址和端口，相互之间能通过localhost来发现和通信
  - 这些容器还可以共享一块存储卷空间
  - Kubernetes中创建、调度和管理最小单位
- Replication Controller
  - 用来控制管理Pod副本，确保Kubernetes有指定数量的Pod副本在运行
  - 是弹性伸缩、滚动升级的实现核心
- Service
  - Service是真实应用服务的抽象
  - 定义了Pod的逻辑集合和访问这个Pod集合的策略
  - Service将代理Pod对外表现为一个单一的访问接口，外部不需要了解后端Pod如何运行
  - 提供了一套简化的服务代理和发现机制
- Label
  - Label是用于区分Pod、Replication Controller、Service的Key/Value对
  - 任意API对象都可以通过Label进行标识
  - 每个API对象可以有多个Label，每个Label的Key只能对应一个Value
  - 通过Label关联Pod和Service，提供一种非常好的松耦合关系
- Node
  - Node可以认为是Pod的宿主机，Pod运行在Node上

## 二、Kubernetes的架构和部署

### 1、Kubernetes的架构和组件

![Kubernetes架构图](/Users/jearry/StudyNote/images/Kubernetes架构图.jpg)

-  Kubernetes属于主从分布式架构，节点在角色上分Master和Node
- 使用Etcd作为存储中间件（通过Raft一致性算法处理日志复制以保证强一致性），使得Kubernetes各组件属于无状态，从而可以更简单地实施分布式集群部署
- Kubernetes Master作为控制节点，调度管理整个系统，包含以下组件
  - Kubernetes API Server
    - 作为Kubernetes系统入口
    - 封装核心对象的增删查改
    - 以REST API接口方式提供给外部和内部组件调用
  - Kubernetes Scheduler
    - 负责集群的资源调度
    - 为新建的Pod分配机器
  - Kubernetes Controller Manager
    - Replication Controller：确保Pod副本数量和定义一致
    - Node Controller：管理维护Node，检查Node健康状态，标识失效的Node
    - Namespace Controller：管理维护Namespace，清理无效Namespace
    - Service Controller：管理维护Service
    - Endpoints Controller：管理维护Endpoints，关联Service 和Pod
    - Service Account Controller：管理维护Service Account
    - Persistent Volume Controller：管理维护Volume和Volume Claim
    - Daemon Set Controller：管理维护Daemon Set，负责创建Daemon Pod
    - Deployment Controller：管理维护Deployment
    - Job Controller：管理维护Job，为Job创建一次性任务Pod
    - Pod Autoscaler Controller：实现Pod的自动伸缩
- Kubernetes Node作为运行节点，用于运行管理业务的容器，包含一下组件：
  - Kubelet：负责管控容器
  - Kubernetes Proxy：负责为Pod创建代理服务
  - Docker：Docker服务

###   2、部署Kubernetes

- Kubernetes是一个分布式架构，可以灵活地进行部署（minikube：可以用于单机测试环境的部署）
- 可以部署在单机，也可以分布式部署
- 机器可以是物理机，也可以是虚拟机
- 示例采用4台虚拟机（CentOS7.0），包含一个Etcd、一个Kubertnetes Master和3个Kubernetes Node

Kubernetes运行环境

| 节点              | 主机名      | IP            |
| ----------------- | ----------- | ------------- |
| Etcd              | etcd        | 192.168.3.145 |
| Kubernetes Master | kube-master | 192.168.3.146 |
| Kubernetes Node 1 | kube-node-1 | 192.168.3.147 |
| Kubernetes Node 2 | kube-node-2 | 192.168.3.148 |
| Kubernetes Node 3 | kube-node-3 | 192.168.3.149 |

#### 1）Etcd

- 下载安装

```
wget https://github.com/coreos/etcd/releases/download/v3.3.1/etcd-v3.3.1-linux-amd64.tar.gz
tar xvzf etcd-v3.3.1-linux-amd64.tar.gz
cd etcd-v3.3.1-linux-amd64
cp etcd /usr/bin/etcd
cp etcctl /usr/bin/etcdctl
```

- 运行

`etcd -name etcd -data-dir /var/lib/etcd -listen-client-urls http://0.0.0.0:2379 http://0.0.0.0:4001 -advertise-client-urls http://0.0.0.0:2379 http://0.0.0.0:4001 >> /var/log/etcd.log 2>&1 &`

- 查看健康状态

`etcdctl -C http://etcd:4001 cluster-health`

#### 2）Kubernetes Master

- 下载安装

```
wget https://github.com/kubernetes/kubernetes/releases/download/v1.7.13/kubernetes.tar.gz
tar xvzf kubernetes.tar.gz
cd kubernetes/server
tar xvzf kubernetes-server-linux-amd64.tar.gz
cd kubernetes/server/bin/
find ./ -perm 755 |xargs -i cp {} /usr/bin/
```

- 运行Kubernetes Master

Kubernetes API Server

```
kube-apiserver --logtostderr=true --v=0 --etcd_serv=http://etcd:4001 --insecure-bind-addre=0.0.0.0 -insecure-port=8080 --service-cluster-ip-range=10.254.0.0/16 >> /var/log/kube-apiserver.log 2>&1 &
```

Kubernetes Controller Manager

```
kube-controller-manager --logtostderr=true --v=0 --master=http://kube-master:8080 >> /var/log/kube-controller-manager.log 2>&1 &
```

Kubernetes Scheduler

```
kube-scheduler --logtostderr=true --v=0 --master=http:kube-master:8080 >> /var/log/kube-scheduler.log 2>&1 &
```

Kubernetes Proxy（可选）

```
kube-proxy --logtostderr=true --v=0 --api_servers=http://kube-master:8080 >> /var/log/kube-proxy.log 2>&1 &
```

#### 3）Kubernetes Node

- Docker

```
curl -sSL https://get.docker.com/ | sh
docker -d -H unix:///var/run/docker.sock -H 0.0.0.0:2375 >> /var/log/docker.log 2>&1 &
```

- Kubelet

```
kubelet --logtostderr=true --v=0 --config=/etc/kubernetes/manifests --address=0.0.0.0 --api-servers=http://kube-master:8080 >> /var/log/kubelet.log 2>&1 &
```

- Kubernetes Proxy

```
kube-proxy --logtostderr=true --v=0 --api_servers=http://kube-master:8080 >> /var/log/kube-proxy.log 2>&1 &
```

#### 4）查询Kubernetes的健康状态

```
kubectl cluster-info
kubectl -s http://kube-master:8080 get componentstatus
kubectl -s http://kube-master:8080 get node
```

#### 5）创建Kubernetes覆盖网络

- Kubernetes网络模型要求每一个Pod都拥有一个扁平化共享网络命名空间的IP，称为PodIP，Pod能够直接通过PodIP跨网络与其他物理机和Pod进行通信。

- 要实现Kubernetes的网络模型，需要在集群中创建一个覆盖网络（Overlay Network），联通各个节点，目前可以通过第三方网络插件来创建覆盖网络，比如Flannel和Open vSwitch

##### 1）使用Flannel

- 在所有Node节点上下载安装

  ```
  wget https://github.com/coreos/flannel/releases/download/v0.10.0/flannel-v0.10.0-linux-amd64.tar.gz
  tar xvzf flannel-v0.10.0-linux-amd64.tar.gz
  cd flannel-v0.10.0
  cp flannel /usr/bin
  ```

- 使用etcd进行配置

  ```
  etcdctl -C http://etcd:4001 set /coreos.com/network/config '{"Network": "10.0.0.0/16"}'
  ```

-  在所有Node节点上运行

  ```
  flanneld -etcd-endpoints=http://etcd:4001 >> /var/log/flanneld.log 2>&1 &
  ```

- Flannel会重新配置Docker网桥，需要先删除原想创建的Docker网桥

  ```
  iptables -t nat -F
  ifconfig docker0 down
  brctl delbr docker0
  ```

- Flannel运行后会生成一个subnet.env，其中包含规划好的Docker网桥网段，根据其中的属性重启Docker

  ```
  source /run/flannel/subnet.env
  docker -d -H unix:///var/run/docker.sock -H tcp://0.0.0.0:2375 --bip=${FLANNEL_SUBNET} --mtu=${FLANNEL_MTU} >> /var/log/docker.log 2>&1 &
  ```

##### 2）使用Open vSwitch

Kubernetes Node的Docker网桥规划

| 节点              | 主机名      | IP            | Docker网桥    |
| ----------------- | ----------- | ------------- | ------------- |
| Kubernetes Node 1 | kube-node-1 | 192.168.3.147 | 10.246.0.1/24 |
| Kubernetes Node 2 | kube-node-2 | 192.168.3.148 | 10.246.1.1/24 |
| kubernetes Node 3 | kube-node-3 | 192.168.3.149 | 10.246.2.1/24 |

- 安装运行Open vSwitch服务（略）
- 下载安装k8s-ovs-ctl工具

```
wget https://raw.githubusercontent.com/wulonghui/docker-net-tools/master/k8s-ovs-ctl
chmod 0750 k8s-ovs-ctl
mv k8s-ovs-ctl /usr/bin/
```

- 在Kubernetes Node上配置 ~/k8s-ovs.env

Kubernetes Node 1

```
DOCKER_BRIDGE=docker0
CONTAINER_ADDR=10.246.0.1
CONTAINER_NETMASK=255.255.255.0
CONTAINER_SUBNET=10.246.0.0/16

OVS_SWITCH=obr0
TUNNEL_BASE=gre
DOCKER_OVS_TUN=tun0

LOCAL_IP=192.168.3.147
NODE_IPS={192.168.3.147 192.168.3.148 192.168.3.149}
CONTAINER_SUBNETS={10.246.0.1/24 10.246.1.1/24 10.246.2.1/24}
```

Kubernetes Node 2

```
DOCKER_BRIDGE=docker0
CONTAINER_ADDR=10.246.1.1
CONTAINER_NETMASK=255.255.255.0
CONTAINER_SUBNET=10.246.0.0/16

OVS_SWITCH=obr0
TUNNEL_BASE=gre
DOCKER_OVS_TUN=tun0

LOCAL_IP=192.168.3.148
NODE_IPS={192.168.3.147 192.168.3.148 192.168.3.149}
CONTAINER_SUBNETS={10.246.0.1/24 10.246.1.1/24 10.246.2.1/24}
```

Kubernetes Node 3

```
DOCKER_BRIDGE=docker0
CONTAINER_ADDR=10.246.2.1
CONTAINER_NETMASK=255.255.255.0
CONTAINER_SUBNET=10.246.0.0/16

OVS_SWITCH=obr0
TUNNEL_BASE=gre
DOCKER_OVS_TUN=tun0

LOCAL_IP=192.168.3.149
NODE_IPS={192.168.3.147 192.168.3.148 192.168.3.149}
CONTAINER_SUBNETS={10.246.0.1/24 10.246.1.1/24 10.246.2.1/24}
```

- 删除原先创建的Docker网桥

```
iptables -t nat -F
ifconfig docker0 down
brctl delbr docker0
```

- 创建Open vSwitch网络

```
k8s-ovs-ctl setup
```

- 重新运行Docker

```
docker -d -H unix:///var/run/docker.sock -H tcp://0.0.0.0:2375 --bridge=docker0 >> /var/log/docker.log 2>&1 &
```

#### 6）安装Kubernetes扩展插件

##### 1）安装Cluster DNS

- Cluster DNS主要用于支持Kubernetes的服务发现机制，主要包含以下几项：

  - SkyDNS：提供DNS解析服务
  - Etcd：用于SkyDNS的存储
  - Kube2sky：监听Kubernetes，当有新的service创建时，生成相应记录到SkyDNS

##### 2）安装Cluster Monitoring

* Cluster Monitoring主体是Heapster，一个容器集群的监控收集工具

* 将收集到的运行平台的监控数据，支持导入到其他第三方系统，比如InfluxDB和GCE

  * InfluxDB集成Grafana提供图表展示功能

##### 3）安装Cluster Logging

- ClusterLogging使用Fluentd+Elastiscsearch+Kibana来收集、汇总和展示Kubenetes运行平台的日志

##### 4）安装Kube UI

```
kubectl create -f kube-ui-rc.yaml
kubectl create -f kube-ui-svc.yaml
```



## 三、Kubernetes快速入门

### 1、示例应用Guestbook

Guestbook包含2部分

- Frontend：web前端，运行3个实例
- Redis：存储，主备模式，1主2备

### 2、准备工作

```
kubectl cluster-info
kubectl -s http://kube-master:8080 get componentstatuses
kubectl -s http://kube-master:8080 get nodes
```

### 3、运行Redis

#### 1）创建Redis Master Pod

```
kubectl create -f redis-master-controller.yaml
kubectl get replicationcontroller redis-master
kubectl get pod --selector name=redis-master
```

#### 2）创建Redis Master Service

```
kubectl create -f redis-master-svr.yaml
kubectl get service redis-master
```

#### 3）服务发现两种机制

- 环境变量：Pod必须在Service之后启动
- DNS：需要安装Cluster DNS


#### 4）创建Redis Slave Pod

- 容器使用镜像gcr.io/google_samples/gb-redisslave:v1

  - 基于redis镜像重写了启动脚本，将作为redis的备节点启动

  ```
  if [[${GET_HOSTS_FROM:-dns} == "env"]]; then
  	redis-server --slaveof ${REDIS_MASTER_SERVICE_HOST} 6379
  else
  	redis-server --slaveof redis-master 6379
  fi
  ```

  - 创建

  ```
  kubectl create -f redis-slave-controller.yaml
  kubectl get replicationcontroller redis-slave
  kubectl get pod --selector name=redis-slave
  ```

#### 5）创建Redis Slave Service

```
kubectl create -f redis-slave-svr.yaml
kubectl get service redis-slave
```

### 4、运行Frontend

#### 1）创建Frontend Pod

```
kubectl create -f frontend-controller.yaml
kubectl get replicationcontroller frontend
kubectl get pod --selector name=frontend
```

#### 2）创建Frontend Service

```
kubectl create -f frontend-svr.yaml
kubectl get service frontend
```

### 5、设置Guestbook外网访问

修改frontend-svr.yaml，设置spec.type为NodePort

```
kubectl replace -f frontend-svr.yaml --force
```

### 6、清理Guestbook

只需删除Replication Controller和Service

```
kubectl delete replicationcontroller redis-master redis-slave frontend
kubectl delete service redis-master redis-slave frontend
```

## 四、Pod

### 1、Pod的基本操作

#### 1）创建Pod

```
apiVersion: v1
kind: Pod
metadata:
  name: hello-world
spec:  #配置pod的具体规格
  restartPolicy: OnFailure              
  containers:
  - name: hello
    image: "ubuntu:14.04"
    command: ["/bin/echo","Hello","world"]
```

```
kubectl create -f def_pod.yaml
```

#### 2）查询Pod

```
kubectl get pod hello-world
kubectl describe pod hello-world
kubectl get pod hello-world --output=go-template --template={{.status.phase}}
```

#### 3）删除Pod

```
kubectl delete pod hello-world
kubectl delete pod --all
```

#### 4） 更新Pod

```
kubectl replace -f def-pod.yaml
kubectl replace --force -f def-pod.yaml
```

### 2、Pod与容器

#### 1） 镜像

```
name: hello
image: "ubuntu:14.04"
imagePullPolicy: Always
```



#### 2）启动命令

#### 3）环境变量

#### 4）端口

#### 5） 数据持久和共享

### 3、Pod的网络

### 4、Pod的重启策略

### 5、Pod的状态和生命周期

### 6、自定义检查Pod

### 7、调度Pod

### 8、问题定位指南







