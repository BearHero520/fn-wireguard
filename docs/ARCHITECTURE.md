# 飞牛 WireGuard：架构与验收约定

## 产品范围

首版将飞牛 NAS 作为 WireGuard 服务端，使用 Go、SQLite、React、TypeScript 和 Vite 8，交付飞牛原生 FPK。主要用户是希望从手机或电脑安全访问家中 NAS 的家庭用户。界面为中文，采用 iOS 18 磨砂质感和 Element Plus 主题蓝的视觉语言；不引入 Vue 组件库。

主流程：进入飞牛应用 → 设置公网地址和 UDP 端口 → 添加设备 → 用 WireGuard 客户端扫码或导入配置 → 查看握手与连接状态。管理页面分为总览、设备管理、连接设置和操作日志。

配置管理支持文件或粘贴导入、预览后确认、导出和复制。服务端导入用于空实例迁移，要求先停止服务且没有现存设备；设备导入必须属于当前 NAS 服务端，地址和密钥不能冲突。标准服务端配置不包含设备私钥，导入后必须标记这些设备为无法导出客户端配置，直到用户补充相匹配的设备配置。

## 模块责任

- React 负责表单、状态呈现、设备配置的本地二维码绘制，不持久化私钥、密码或会话令牌。
- Go HTTP 服务负责鉴权、输入校验、业务事务和静态资源。
- SQLite 保存设置、设备、会话与审计记录。WireGuard 私钥和预共享密钥在入库前使用 AES-256-GCM 加密；数据库本身不宣称为整体加密。
- 独立主密钥文件保存在应用私有数据目录，使用限制性文件权限。复制数据库和主密钥会获得解密能力；这不是抵御 NAS root 用户的边界。
- Linux 适配层只管理专用的 `fnwg0` 接口；不修改 NAS 默认路由、DNS 或不相关的防火墙规则。
- FPK 生命周期脚本负责启动、停止与包升级。持久数据必须位于飞牛提供的持久目录，不能存放在会被升级替换的程序目录。

0.1.2 增加独立的 root 维护命令，仅迁移旧版本遗留文件的元数据。实际故障表现为旧 `app.log`、`master.key` 和 `state.db` 归 root 且模式为 0700，降权后的服务在打开日志时便退出。迁移工具不读取或重建秘密内容，只处理固定文件清单；通过目录与文件描述符验证所有者、文件类型和链接数，保留原数据。迁移失败时封闭数据目录并拒绝启动，部分已经完成的元数据变更可在下一次重试中继续处理，不宣称原子回滚。生命周期入口与应用专用路径由飞牛受信任安装环境提供。

0.1.3 将生命周期锁内置于 `cmd` 脚本。预升级阶段只使用旧版本已经存在的资源，不从尚未替换的 `app/` 加载新 helper；预升级和预卸载的停止逻辑也不依赖另一个版本的 `main`。新程序的权限整理和数据迁移在应用新包后的回调阶段执行。升级回归必须执行“旧应用文件 + 新生命周期脚本”的组合，不能仅检查完整新包的静态内容。

## 身份与传输边界

原生模式通过飞牛网关和 Unix socket 访问。只有在 socket 模式下才允许信任飞牛转发的管理员身份，TCP 模式禁止使用这些请求头作为认证凭据。每个管理 API 都必须验证管理员身份；NAS 登录不能代替应用内授权校验。

开发模式使用独立的本地管理员和受保护会话。密码采用 Argon2id 派生，随机会话令牌仅保存哈希；Cookie 使用 HttpOnly 和 SameSite，写操作验证 CSRF 令牌。首次本地初始化需要私有数据目录中的 bootstrap token。

按用户要求，管理页面支持飞牛 HTTP 和 HTTPS 入口，不在前端阻止 HTTP，也不在 FPK 默认启动参数中强制 Secure Cookie。HTTPS 保留为安全建议；手动启用 `--secure-cookie` 时仍要求 HTTPS，直接使用 TLS 启动二进制时自动启用。HTTP 模式保留网关管理员鉴权、HttpOnly、SameSite 和 CSRF 校验。WireGuard 加密隧道数据不等于 HTTP 管理网页已加密。二维码和 `.conf` 导出包含设备私钥，必须由用户明确触发，响应禁止缓存，关闭窗口后从界面状态中清除。

原生 HTTP 兼容模式使用独立的 `fnwg_session_http` Cookie 名；HTTPS-only 和本地模式保留 `fnwg_session`。浏览器会拒绝非安全来源覆盖已有的同名 Secure Cookie，因此仅删除 Secure 标记不足以处理从旧版 HTTPS 会话切换到 HTTP 的情况（[IETF Cookie 存储规则](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis/#section-5.7)）。会话创建、读取、注销及导入令牌所有者统一采用模式对应的名称，避免管理员升级后陷入重复登录。

导入器仅解析允许的标准 WireGuard 字段，拒绝 `PreUp`、`PostUp`、`PreDown`、`PostDown` 等可执行钩子，不调用 shell 执行上传文件。导入预览令牌绑定当前会话、限制有效期和缓存数量，并在应用时重新验证运行状态及冲突。导入输入、私钥和完整配置不会进入操作日志。

## 运行状态与一致性

- 在线状态来自真实的近期 WireGuard 握手，不根据“已启用”推测在线。
- Windows 本地开发允许管理设备、验证界面和配置导出，但明确显示 WireGuard 不可用，不制造在线数据。
- 停用或删除设备时，必须同时处理真实接口与持久数据，失败不可返回虚假的成功。
- 运行期间禁止修改服务端网络设置，避免切断当前连接或产生数据库与内核不一致。
- 连接地址、DNS、客户端 AllowedIPs 与保活仅用于配置导出，不依赖服务运行状态；监听端口和隧道地址修改仍需确认服务停止。自动 DNS 以空字符串保存，导出时省略 DNS 字段，不替换客户端当前网络解析设置。
- 已有设备时禁止直接更换分配地址段，避免已有配置静默失效。
- 不自动打开路由器端口或提供未经用户配置的公网穿透。公网可达性和 UDP 端口转发属于安装环境准备。
- 0.1.6 默认访问主家庭 IPv4 网段。客户端 AllowedIPs 仅生成路由，服务端 nftables 对每个源客户端及目标 IP 独立执行权限限制。

## 交付验收

1. Go 单元/集成测试覆盖鉴权、CSRF、加密、地址分配、危险输入和配置导出。
2. React TypeScript 检查和 Vite 8 正式构建通过。
3. 本地验证初始化、登录、保存连接信息、添加设备、下载配置、停用/删除和操作日志。
4. Linux 目标编译通过，FPK 包由官方 fnpack 构建并校验关键内容。
5. 单独记录尚未在真实飞牛设备上验证的网关、安装生命周期和 WireGuard 握手，不将本地通过等同于真机验收。

## 开发分工

项目作者与维护者为 BearHero520。Go 服务、React 界面与飞牛 FPK 适配在同一仓库维护；界面状态必须与 API 和实际运行环境一致。

## 0.1.5 端口一致性

数据库/API 保留 WireGuard 标准 `endpoint`（host:port）与 `listenPort`，不做破坏性数据迁移。界面表单通过 `connectionDraft` 拆分地址与端口；默认保存时由当前服务端口重新组装 Endpoint，避免旧端口残留。已有 NAT 映射差异会显式展示并保留。

`POST /api/server/port-check` 复用管理员会话、来源和 CSRF 验证，只接受 1–65535 整数。先读取受本应用拥有且处于 UP 状态的接口及内核实际端口；同端口已由本应用运行时直接报告 active。其他情况临时绑定 IPv4/IPv6 UDP 通配地址，结束立即关闭，不发送数据。权限不足或运行状态不明报告 unknown，不猜测为空闲；开发模式同样不伪造已生效。窗口检查后仍可能发生竞争，以真正启动时的内核操作及回读验证为准。

Linux 直接使用默认独占 UDP 绑定；Windows 本地测试使用 Winsock `SO_EXCLUSIVEADDRUSE`，避免通配地址探测漏掉绑定在指定 IP 的监听（[Microsoft 文档](https://learn.microsoft.com/en-us/windows/win32/winsock/using-so-reuseaddr-and-so-exclusiveaddruse)）。不执行进程终止、端口释放、防火墙或路由器更改。

## 0.1.6 访问权限与转发

Settings 保存 accessMode（lan/selected/custom）、allowedDevices 及检测到的 LAN 元数据；peer_access 独立表保存客户端 inherit/lan/selected 覆盖，外键随 peer 删除。避免改变已有 peers 表及密钥布局。旧默认路由可迁移；定制路由保留。受限设备不能为空、重复、超出主家庭子网或使用网络/广播地址。

启用服务时先校验 LAN 元数据、IPv4 转发、隧道重叠及 nft 依赖。接口在 DOWN 状态下准备规则和 WireGuard 配置，成功后才 UP。运行中的客户端变更原子替换 nft 规则，再更新内核 peer；失败恢复旧运行配置，SQLite 事务失败同样回滚。停止先删除受应用所有权标记保护的接口，再清理本应用规则。

独立 inet fnwg_access 表带所有权 comment；input/forward 在 -10 优先级先执行源客户端 /32 和目的范围限制，未授权的 fnwg0 流量最终 DROP（包括 IPv6 与客户端互访）。postrouting 仅对已授权流量 masquerade，免于在路由器配置返回路由。选择 NAS 时兼容通过 NAS 地址访问的 DNAT 容器服务。

nft 的单个 base chain ACCEPT 不能覆盖另一个 chain 的 DROP。遇到 iptables-nft 的 ip/filter/FORWARD，添加两个能被 iptables 表达的简易兼容入口（fnwg0 + 隧道网段 + 回程连接状态）；精细 ACL 在较早的独立 inet chain，复杂集合不会混入 iptables 管理链。入口与 ACL 在同一 nft 事务中更新；清理仅按本应用精确 comment 与 handle 删除，不更改现有策略或其他应用规则。其他自定义防火墙仍可能阻止流量；宿主机整体清空规则或重置 Docker 后，应停止再启动 VPN 重建。

应用生命周期 root 部分仅在需要时开启 net.ipv4.ip_forward；服务进程仍以专用用户 + NET_ADMIN 运行。共享转发设置不会在停止时关闭，不更改默认网关、NAS DNS 或路由器。配置文件导入导出不包含客户端访问策略，不构成完整备份。

设计依据：[nftables 命令与链语义](https://netfilter.org/projects/nftables/manpage.html)、[Docker 转发过滤行为](https://docs.docker.com/engine/network/firewall-iptables/)。

## 0.1.7 归属读取与错误恢复

表 comment 优先取 JSON；字段缺失时才调用 `nft -s -a list table inet fnwg_access`。只接受匹配快照句柄的固定表头及其下一行的完整表归属标记，不接受嵌套链/规则注释；显式空值或外部标记拒绝操作。删除按句柄，新建使用 create，保持整个替换在一个 nft 事务内。读后同名表被重建时不能按名字误删，事务中的冲突也不能静默接管。

`runtimeUnchangedError` 仅表示 nft 事务发出前的检查失败，此时 Apply 未修改运行状态，直接返回并保留数据库，无需回滚或锁定。事务已发出后的错误（包括超时）不能标记为未修改，仍尝试恢复旧规则和 peer；恢复成功清空 runtimeError，失败保留锁定。原操作失败仍向请求方返回错误，不把“恢复成功”当作“新设置成功”。数据库提交失败的回滚使用相同恢复原则。
