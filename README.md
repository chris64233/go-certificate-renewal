# go-certificate-renewal

用于承载证书订单、域名挑战与签发状态管理相关的 Go 服务代码。

开发环境：Go 1.23.0。

## 功能概览

本服务支持**聚合多域名的证书续期订单**，核心能力：

- **订单创建**：创建时冻结域名集合（去重、排序）与截止时间，为每个域名单独生成挑战。
  挑战秘密的明文只在创建响应中返回一次，存储中仅保留其 SHA-256 安全摘要。
- **挑战回调**：支持重复、乱序、迟到的回调投递。
- **取消 / 过期推进 / 签发确认 / 查询**：完整的订单生命周期管理与 outbox 持久化。

## 订单状态机

```
PENDING --(全部挑战成功)--> READY_FOR_ISSUANCE --(签发确认)--> ISSUED
PENDING --(取消)--> CANCELLED
PENDING --(超过截止时间)--> EXPIRED
READY_FOR_ISSUANCE --(取消)--> CANCELLED
```

`CANCELLED`、`EXPIRED`、`ISSUED` 为终态。任何回调都不能使订单离开终态：
取消或过期后到达的成功回调不会复活订单；已签发订单上的重复回调返回与首次一致的稳定结果。

## 并发与一致性设计

- 服务层所有变更操作在单互斥锁下串行执行（`Service.mu`），因此：
  - “全部挑战成功 → 原子转为 `READY_FOR_ISSUANCE` + 写出**唯一一条**签发 outbox”
    不会被并发到达的最后几个回调多发或漏发；
  - 取消、过期推进、签发确认两两竞争时有确定结果（锁内先到者胜）。
- **惰性过期**：回调或取消到达时若已超过截止时间，PENDING 订单就地转为 `EXPIRED`，
  不依赖后台过期推进的时序，保证竞争结果确定。
- 单个域名的挑战失败只记录在该挑战上，不污染其他域名的状态。
- 挑战结果**先到先定**：已出结论的挑战不会被后续不同回调号的回调推翻。

## 回调幂等规则

以 `(订单 ID, 回调号)` 为键记录每次回调的判定结果（含内容摘要）：

| 情况 | 行为 |
| --- | --- |
| 回调号 + 内容都相同 | 复用首次处理结果（`Duplicate=true`），不产生副作用 |
| 回调号相同、内容不同 | 返回 `KindIdempotency` 冲突错误 |
| 认证失败（秘密不匹配） | 返回 `KindAuth`，**不**写入回调记录，修正秘密后可重试同一回调号 |
| 订单已终态 | 记录回调并返回稳定结果，不改变订单状态 |

## 错误分类

所有领域错误为 `*certificaterenewal.Error`，用 `IsKind(err, kind)` 判定类别：

| Kind | 含义 |
| --- | --- |
| `KindAuth` | 认证失败，如挑战秘密不匹配 |
| `KindExpired` | 订单已超过截止时间 |
| `KindState` | 当前状态不允许该操作（状态机冲突） |
| `KindIdempotency` | 幂等冲突：同一回调号携带不同内容 |
| `KindNotFound` | 订单或挑战不存在 |
| `KindInvalid` | 请求参数不合法 |

## 持久化

`Store` 接口抽象了订单、挑战、回调记录与 outbox 的存储，默认提供内存实现
`InMemoryStore`（返回深拷贝，可安全并发使用）。跨实体写入的原子性当前由服务层
串行化保证；替换为数据库实现时应将对应操作放入同一事务。

## API 一览

```go
s := certificaterenewal.NewService(certificaterenewal.NewInMemoryStore(), nil)

order, challenges, _ := s.CreateOrder(certificaterenewal.CreateOrderInput{
    Domains:  []string{"a.example.com", "b.example.com"},
    Deadline: time.Now().Add(24 * time.Hour),
})
// challenges[i].Secret 为明文秘密，仅此一次可见

res, _ := s.HandleChallengeCallback(certificaterenewal.CallbackInput{
    OrderID: order.ID, Domain: "a.example.com",
    CallbackID: "cb-1", Secret: "...", Succeeded: true,
})

s.CancelOrder(order.ID)        // 取消（幂等）
s.AdvanceExpiry()              // 推进过期，返回本次过期的订单 ID
s.ConfirmIssuance(order.ID)    // 签发确认（幂等）
view, _ := s.GetOrder(order.ID) // 查询订单与挑战
msgs, _ := s.ListOutbox()       // 拉取签发 outbox
```

## 运行测试

```sh
go test -race ./...
```

测试覆盖：订单创建冻结与秘密摘要、回调幂等（重复/冲突/认证）、失败隔离、
取消与过期后回调不复活、签发后重复回调稳定、并发末批回调只写一条 outbox、
取消与签发确认竞争的确定性等。
