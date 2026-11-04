# someip

纯 Racket 实现的 SOME/IP 协议栈。

`someip` 在标准 Racket 发行版之上实现 AUTOSAR **SOME/IP**（Scalable
service-Oriented MiddlewarE over IP）协议族——纯 Racket，无外部库、
无 FFI：

- **SOME/IP 消息编解码** —— 16 字节头严格校验、消息类型、返回码、
  TCP Magic Cookie、单数据报多消息拆包。
- **载荷序列化框架** —— 字节序、对齐与长度字段大小可配置；基本
  类型、带 BOM 的 UTF-8/UTF-16 字符串、定长/变长数组、带长度字段的
  结构体、联合体，以及 TLV 标签（未知成员按线类型跳过）。
- **SOME/IP-TP** —— 大载荷 UDP 分段与容错重组（乱序、重复、空洞
  检测）。
- **SOME/IP-SD** —— 完整线格式（条目、选项、IPv4/IPv6
  Endpoint/Multicast/SD Endpoint）与确定性的服务端/客户端状态机：
  Initial Wait / Repetition / Main 三阶段，find/offer/subscribe
  生命周期，TTL 刷新，对端重启检测。
- **传输层** —— UDP 端点（组播组加入）与 TCP（按长度字段分帧、
  连接复用）；单数据报或单 TCP 段内的多条 SOME/IP 消息自动拆分。
- **Provider/Consumer API** —— 基于 UDP/TCP 的方法、事件、字段与
  发布/订阅，可选服务发现。

设计目标是可嵌入的测试与工具链场景：为 Racket 侧与汽车 ECU 通信
（诊断、设备仿真、报文回放、车载数据服务）提供一套完整、确定性的
协议栈。

## 安装

```
raco pkg install someip
```

或从 Git 检出安装：

```
raco pkg install --link ./someip
```

## 快速上手

服务端：

```racket
#lang racket/base
(require someip)

(define ep
  (make-someip-endpoint
   #:udp-port 30490
   #:multicast-groups '("239.255.1.100")
   #:message-handler void))

(define provider
  (make-service-provider
   #:endpoint ep
   #:service-id #x4321
   #:instance-id 1
   #:interface-version 1
   #:methods
   (list (method #x0001
                 (lambda (payload sender)
                   ;; 请求载荷进，响应载荷出
                   (bytes (add1 (bytes-ref payload 0))))))
   #:events
   (list (event #x8010 #x1))
   #:multicast-address "239.255.1.100"))

;; 路由入站的 SD 与服务消息，应答请求
(provider-message-handler provider)

(provider-start! provider)              ; SD offer 生命周期
(provider-notify! provider #x8010 #"hello subscribers")
```

消费端：

```racket
#lang racket/base
(require someip)

(define ep (make-someip-endpoint
            #:multicast-groups '("239.255.1.100")
            #:message-handler void))
(define consumer
  (make-service-consumer
   #:service-id #x4321
   #:interface-version 1
   #:eventgroup-ids '(#x1)
   #:multicast-address "239.255.1.100"))

(consumer-attach-endpoint! ep consumer)

(consumer-set-event-callback!
 consumer #x8010 (lambda (payload sender) (printf "event: ~a\n" payload)))

(consumer-start-discovery! consumer)    ; SD find/subscribe 生命周期

(define result (consumer-call consumer #x0001 #:payload (bytes 20)))
(call-result-payload result)            ; => #"\x15"
```

静态拓扑（不用 SD）时，给 consumer 传 `#:server-host`/`#:server-port`
即可，跳过发现流程。

传输端点通过 custodian 持有线程；调用 `endpoint-close!` 可确定性地
整体拆除。

## 线格式符合性

实现遵循 AUTOSAR Foundation 规范（SOME/IP Protocol、SOME/IP-SD，
R22-11 版），测试套件对其做字节级验证，包括规范自带的示例（5880
字节 TP 分段示例、SD 示例 PDU、TCP Magic Cookie）。已知的规格笔误
裁定与文档化偏差均写在模块文档中。

## 平台说明

UDP 组播在 macOS、Linux、Windows 上行为一致；端点显式选择临时端口
（Racket 未提供 listener 端口查询）。本包只依赖 `#lang racket/base`
与 `racket/tcp`/`racket/udp`，Racket CS 可运行之处皆可运行。

## 文档

完整模块文档由 `scribblings/` 渲染：

```
raco docs someip
```

## 开发

```
raco test .
raco setup --check-pkg-deps someip
```

## 许可证

[Apache-2.0](LICENSE)

English README: [README.md](README.md)。
