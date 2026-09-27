# task26092728

威胁情报 IOC 入库组件（纯 Go 标准库，无第三方依赖）。支持 SHA-256、IPv4、IPv6、域名四类指标的判定、规范化、去重与本地持久化。

## API

- `Open(dir)`：打开或创建存储，记录持久化在 `dir/store.json`，重新打开后仍在。
- `Normalize(raw)`：纯函数，返回 `NormResult{OK, Kind, Normalized, Reason}`。
- `Ingest(items)`：按输入顺序逐条返回 `Created / Existing / BatchDup / Rejected`；单批超过 1000 条整批拒绝（`ErrTooManyItems`）；命中已有记录与批内重复都会把来源并入对应记录。
- `Defang(id)`：域名/IPv4 的 `.` → `[.]`，IPv6 的 `:` → `[:]`，哈希原样。

## 规范化要点

- 先 trim 首尾空白，再把 `[.]` `(.)` `{.}` `[dot]` `(dot)`（dot 不分大小写）还原为 `.`、`[:]` 还原为 `:`。
- SHA-256：恰好 64 位十六进制，转小写。
- IPv4：严格四段十进制 0–255，拒绝前导零 / 其他进制 / 整数形式 / 省略段。
- IPv6：接受压缩、大写、点分尾段、整体方括号；拒绝 zone id；规范形式为 RFC 5952 §4 纯十六进制；`::ffff:0:0/96` 内的 IPv4-mapped 地址归入对应 IPv4 记录。
- 域名：RFC 1123 标签规则，至少两个标签，顶级标签不能全数字，去末尾单根点并转小写；非 ASCII 标签按 RFC 3492 编码为 `xn--` 形式（`punycode.go` 内置编码器），总长 ≤ 253。

## 测试

```sh
go test ./...
```

`ioc_test.go` 覆盖：四类指标的等价变体同批入库只产生一条记录、近似反例全部被拒且不影响同批合法条目、所有记录的 `Defang` 输出经 `Normalize` 往返回到自身规范形式、批次上限与重开持久化。
