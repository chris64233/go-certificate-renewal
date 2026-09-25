# go-certificate-renewal

用于承载证书订单、域名挑战与签发状态管理相关的 Go 服务代码。

开发环境：Go 1.23.0。

运行测试：

    go test ./...

## 功能概览

`Service` 支持聚合多域名挑战的证书续期订单，提供六个操作：

| 方法 | 说明 |
| --- | --- |
| `CreateOrder` | 创建订单：冻结域名集合与截止时间（创建时刻 + TTL），为每个域名生成独立挑战 |
| `HandleCallback` | 处理挑战回调，支持重复、乱序、迟到投递 |
| `CancelOrder` | 取消订单（active / pending_issuance 可取消，重复取消幂等） |
| `AdvanceExpiry` | 过期推进：把已过截止时间的 active 订单置为 expired |
| `ConfirmIssuance` | 签发确认：pending_issuance → issued，并办结 outbox |
| `GetOrder` / `ListOutbox` | 查询订单与挑战状态（不暴露秘密摘要）、轮询 outbox |

### 订单状态机

```
active --(全部域名挑战成功)--> pending_issuance --(签发确认)--> issued
active --(取消 / 过期)--> cancelled / expired
pending_issuance --(取消)--> cancelled   （同时作废已写出的 outbox）
```

`cancelled`、`expired`、`issued` 均为终态，任何迟到回调都不能让订单复活。

## 关键设计

### 挑战秘密只持久化摘要

创建订单时为每个域名生成随机秘密，明文仅在 `CreateOrderResult.Secrets` 中返回一次；
持久化的只有 `HMAC-SHA256(digestKey, orderID | domain | secret)` 摘要（绑定订单与域名）。
回调时重新计算摘要比对，不匹配返回 `auth` 类错误。使用 `FilePersister` 跨进程重启时，
需通过 `WithDigestKey` 提供稳定密钥。

### 回调幂等与域名隔离

- 每个回调以 `CallbackID` 为幂等号：**同号同内容**复用首次处理结果（`Reused=true`），
  **同号异内容**返回 `conflict` 类错误。
- 挑战状态按域名独立维护：一个域名失败只影响该域名，其他域名可继续推进；
  已终结（succeeded/failed）的挑战不能被新回调覆盖。
- 即使订单已签发，重复回调仍通过幂等记录返回稳定结果。

### 原子签发转换与唯一 outbox

所有状态变更都在同一把互斥锁内完成“检查 + 迁移 + 持久化”：当订单仍有效且全部域名
挑战成功时，订单原子转为 `pending_issuance` 并写出**唯一一条**签发 outbox
（ID 为 `outbox-<orderID>`）。并发到达的最后几个回调中只有一个能完成迁移，
其余收到 `state` 类错误，保证 outbox 不重不漏。

### 取消 / 过期 / 签发的确定性竞争

- 取消与过期只作用于 `active`（取消额外覆盖 `pending_issuance`），签发确认只作用于
  `pending_issuance`；谁先持锁谁生效，结果确定。
- 取消或过期后到达的成功回调返回 `state` / `expired` 错误，不改变任何状态。
- 回调与取消路径内置**惰性过期**：超过冻结截止时间即置为 `expired`，
  不依赖 `AdvanceExpiry` 是否已运行。

### 错误分类

`KindOf(err)` 可提取错误类别：

| Kind | 含义 |
| --- | --- |
| `not_found` | 订单不存在，或域名不在冻结的域名集合中 |
| `auth` | 挑战秘密摘要校验失败 |
| `expired` | 订单已超过冻结的截止时间 |
| `state` | 当前状态不允许该操作（重复完成挑战、取消已签发订单等） |
| `conflict` | 幂等冲突：同一幂等号携带不同内容 |
| `validation` | 请求参数不合法（空域名、重复域名、非正 TTL 等） |

### 持久化

`Persister` 接口抽象快照存取，内置两种实现：

- `MemoryPersister`：进程内，主要用于测试；
- `FilePersister`：JSON 落盘，写临时文件后原子 rename，重启后经 `NewService` 自动恢复。

## 代码结构

- `model.go` — 订单、挑战、outbox、回调记录等数据模型与状态枚举
- `service.go` — 业务逻辑：创建、回调、取消、过期推进、签发确认、查询
- `store.go` — `Persister` 接口与内存 / JSON 文件实现
- `errors.go` — 错误分类（`Kind`）与 `KindOf`
- `service_test.go` — 单元测试与并发竞争测试（`-race` 通过）
