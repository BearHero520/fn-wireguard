# 飞牛 fnOS 原生应用

本项目按官方 Native 应用格式打包为 `.fpk`，通过应用中心手动安装。服务是 Go Linux 原生程序，SQLite 和 Web 文件随包部署，不依赖 Docker。

## 构建

在 Windows PowerShell 中，从项目根目录运行：

```powershell
./scripts/build-fpk.ps1
# ARM64 包
./scripts/build-fpk.ps1 -Architecture arm64
```

脚本执行前端 `npm ci` / `npm run build`、CGO 禁用的 Linux Go 交叉编译，并调用官方 fnpack 1.2.3。首次构建会下载官方 Windows fnpack 到项目 `.tools`，不会安装到系统目录。现有工具可通过 `-Fnpack C:\path\fnpack.exe` 指定。构建必须提供有效应用图标 `packaging/fnos/ICON.PNG`（64px）、`ICON_256.PNG`（256px）及 `app/ui/images/icon_64.png` / `icon_256.png`。产物位于 `dist`，脚本输出 SHA-256。

每次构建使用独立 staging 目录，分别输出 `dist/fn-wireguard-amd64.fpk` 和 `dist/fn-wireguard-arm64.fpk`，不会修改源码中的 manifest 或混入旧的前端资源。官方 Windows fnpack 1.2.3 生成的 TAR 中可执行文件模式实际为 0666；构建随后运行标准库 Go 工具 `scripts/fpk-permissions.go`，将生命周期脚本、服务程序及固定 launcher 设为 0755，并更新内层 `app.tgz` 的 manifest MD5。该步骤依据当前工具产物格式；未知格式会失败。最终需要在真实 NAS 验证应用中心安装验收。

## 系统条件

- 当前入口使用统一网关；官方国内版示例要求 fnOS >= 1.1.3100。该最低版本是 API 要求，不表示已经完成该版本实机兼容验证。
- NAS 必须有 WireGuard 内核支持，以及 `ip`（iproute2）和 `setpriv`（util-linux，支持 ambient capabilities）。安装前检查命令，缺失时给出中文错误；安装脚本不修改 NAS 软件源或自动安装系统软件。Go 通过官方 wgctrl 的 Linux netlink 接口直接控制 WireGuard，不需要系统 `wg` 可执行文件。
- x86 包使用 Go `linux/amd64`，ARM 包使用 `linux/arm64`，分别声明 `platform=x86` / `platform=arm`。

## 身份与权限

应用仅监听 `${TRIM_PKGVAR}/app.sock`，安装目录中的 root 控制链接 `${TRIM_APPDEST}/app.sock` 指向它。网页入口为 `/app/fn-wireguard/`。飞牛统一网关检查 NAS 登录态；服务通过 `--auth-mode fnos` 验证网关提供的 `X-Trim-Userid` 和 `X-Trim-Isadmin=true`，管理接口只允许 NAS 管理员。服务保留独立 CSRF 校验。不要将同一 fnOS 鉴权服务改为普通 TCP 监听，否则客户端可能伪造这些 Header。

原生服务支持通过飞牛 HTTP 或 HTTPS 入口打开并保持管理会话，默认不设置 `--secure-cookie`。HTTP 请用于可信网络；建议启用 HTTPS 保护管理会话和配置传输。二进制仍提供可选的 `--secure-cookie` 参数，适用于明确只允许 HTTPS 的部署。应用继承 NAS 网关域名和证书，不自动配置或申请 TLS 证书。

升级后应用会自动建立新的 HTTP 兼容会话，无需清除旧 HTTPS Cookie；NAS 自身登录态仍由飞牛系统管理。

0.1.4 兼容飞牛网关移除 Host 端口的转发方式。本机只读检查发现 `/app/` 使用 `proxy_set_header Host $host`；浏览器的 Origin 仍可能包含 `:5000` 或 `:5001`，导致旧版在保存设置和启动服务时错误拒绝请求。仅 fnOS 网关模式允许“相同主机、网关 Host 未带端口”的情况；若 Host 保留端口则仍精确比较。不同主机、异常 Origin、浏览器明确标记的跨来源请求仍拒绝，管理员身份、UID 会话绑定和 CSRF 校验不变。不从未验证的 X-Forwarded-Host 扩大信任范围。普通 TCP 本地模式保持原有端口校验。相关行为见 [NGINX 官方代理头说明](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_set_header)。

包声明 root 生命周期权限，但长期 Web 服务通过 `setpriv` 切换到专用应用用户，清除附加用户组，只保留 `CAP_NET_ADMIN`（inheritable、ambient、bounding），并启用 `no-new-privs`。没有 root 服务回退。固定服务脚本在降权后才打开日志。root 不递归修改用户数据的权限或所有权；应用安装目录和程序保持系统控制，PID 位于 root 管理的配置目录。

安装和升级回调明确将包目录、server 目录、程序及服务脚本设为 root 所有、0755，拒绝 executable/helper 符号链接；前端包资源 root 所有，仅供应用用户读取。只有用户数据目录归应用用户所有。

0.1.2 在安装、升级及停止状态下启动时，共用 root 控制的数据维护程序，迁移旧版本遗留的 root 所有文件权限。维护仅处理固定的 `master.key`、`state.db`、SQLite WAL/SHM 和应用日志等已知文件元数据，保留原密钥、数据库和日志内容；通过文件描述符验证普通文件、单硬链接和允许的所有者，再移交专用应用用户并设为 0600。不递归更改数据，不跟随符号链接，不读取密钥或数据库内容。发现不安全结构或数据库存在但密钥缺失时拒绝启动，并显示具体维护错误。

启动、停止和安装/升级回调通过 root 私有目录中的 `lifecycle.lock` 串行执行，长期服务不会继承锁。维护程序还检查 `/proc` 中对应服务程序，包括已删除的旧程序；发现存活进程或无法确认状态时拒绝迁移，避免修改仍在使用的数据库文件权限。需要 util-linux 的 `flock`。

0.1.3 修复 0.1.2 的预升级阶段依赖错误。飞牛先执行 `upgrade_init`，再应用新包；此时 `TRIM_APPDEST` 仍是旧版本，不能从中加载新增加的锁程序。锁逻辑现已内置在生命周期脚本中，预升级和预卸载独立停止旧服务，不调用可能属于其他版本的 `main`，也不访问新数据维护程序。数据迁移留到新包应用后的回调阶段执行。

排查 0.1.2 升级失败时，只读检查确认 NAS 已回滚到完整的 0.1.1，因此交付 0.1.3 供应用中心直接更新。随后排查 0.1.4 问题时，已确认 NAS 安装的是 0.1.3，Web 服务已启动；数据库中的连接地址仍为空，且没有成功保存的操作记录。两次检查均未修改 NAS 配置、权限或运行状态。

本地生命周期回归可运行 `python scripts/lifecycle-smoke.py`。它用 Git Bash 执行实际生命周期脚本，模拟旧应用文件和新升级脚本并存的阶段；身份、文件所有权和系统命令使用测试替身。这能验证升级脚本的执行路径，不能替代真实 Linux 权限、网关或 WireGuard 运行验证。

0.1.3 发布验证：从原 0.1.2 FPK 提取的升级脚本在旧应用文件上复现了同一条“生命周期锁程序缺失”错误；修正版通过 15 项执行回归，涵盖混合版本、损坏的相邻 `main`、锁冲突、停止与状态查询、匹配及不匹配 PID、已删除程序路径和安装/升级回调。最终双架构 FPK 的脚本字节与通过验证的源码一致，ELF 架构、权限、前端文件及包内校验值均已核对。带版本号的发布文件位于 `dist/releases/0.1.3/`；未在 NAS 安装或启动本版本。

该互斥覆盖正常 fnOS 生命周期入口；不保证绕过入口、直接以 root 同时手工启动服务和维护工具的情况。本次 NAS 排查仅执行只读检查，未在 NAS 执行迁移或更改文件权限。维护实现完成本地测试和 Linux 双架构交叉编译，但尚无真实 Linux 迁移执行验证。

`CAP_NET_ADMIN` 能修改 NAS 网络，并不只限于一个接口。程序通过固定接口名和归属标签限制操作范围；仍须在实机验证权限继承与网络行为。后续进一步隔离可采用独立受限特权助手。

服务 socket 设为应用用户可读写（0600），数据目录 0700。官方文档只规定 gatewaySocket 为文件名，没有承诺网关运行用户或符号链接解析策略。当前目标 NAS 的 0.1.3 已能从飞牛桌面进入应用；其他 fnOS 环境仍需验证网关连接。如果网关不是 root，应授予经验证的网关组精确权限，不应开放 socket 为任意用户可写，也不应静默回退为 root Web 服务。

## 运行与数据

`cmd/main` 接收 start、stop、status；status 返回 0 表示运行、3 表示停止。它记录准确 PID 并检查 `/proc/<pid>/exe`，停止发送 TERM 等待正常退出。数据和日志位于 `${TRIM_PKGVAR}`，安装、更新不会主动删除数据库或密钥。升级前和卸载前显式停止应用服务，服务退出时只移除自己管理的 WireGuard 接口；升级回调保证数据目录存在。卸载不主动删除数据库、密钥或持久配置。再次启动时会恢复数据库中的期望服务状态。

安装本身不会启用 VPN。启动应用后仍需在管理页填写公网地址、端口、隧道网段及访问范围；路由器需要将所选 UDP 端口转发到 NAS。WireGuard 流量经 UDP 传输；NAS 网页网关不代替 UDP VPN 的公网可达性。

管理页支持预览导入服务器或客户端 `.conf`，确认后应用；支持导出或复制配置。服务器文件不记录自身公网域名，导入后应核对页面上的公网 Endpoint。标准服务器文件只含设备公钥；这些设备在导入后不能导出客户端私钥，可通过导入该设备原有的客户端文件恢复导出能力。导入不会执行 `PostUp` 等脚本钩子，并拒绝不支持的配置字段、地址冲突以及覆盖非空服务器。

0.1.4 的连接地址可只填写域名或 IP，保存时补齐监听端口，也可填写独立的公网端口。页面显示未保存状态、表单内错误及保存结果；成功后立即更新连接地址，并防止较早的刷新响应覆盖它。连接地址、DNS、客户端路由和保活参数只影响导出的客户端配置，可在服务运行时保存；监听端口和隧道地址仍受停机校验约束。

客户端 DNS 默认“自动 · 沿用设备当前网络”：导出的配置不含 DNS 覆盖项，由手机或电脑继续使用当前 Wi-Fi、移动网络的解析设置。可切换为手动 DNS。升级保留已经保存的 DNS 地址；已有 `1.1.1.1` 时选择“自动”并保存即可。变更后需重新导出并在设备上导入配置；已经导入的旧配置不会自动修改。DNS 字段语义见 [WireGuard 官方 wg-quick 文档](https://git.zx2c4.com/wireguard-tools/about/src/man/wg-quick.8)。

实机验收至少覆盖首次安装、启停、升级保留数据、管理员/普通用户权限、网关 socket 权限、创建和撤销设备、真实客户端握手、NAS/LAN 访问、网络接口清理以及卸载行为。Windows 上构建成功不能证明 NAS 内核与防火墙实际兼容。

## 官方依据

- [官方完整文档快照](https://developer.fnnas.com/llms-full.txt)
- [fnpack CLI](https://developer.fnnas.com/docs/cli/fnpack)
- [Native 示例](https://developer.fnnas.com/docs/examples/native)
- [Manifest](https://developer.fnnas.com/docs/core-concepts/manifest)
- [应用框架与生命周期](https://developer.fnnas.com/docs/core-concepts/framework)
- [统一网关与鉴权 Header](https://developer.fnnas.com/docs/core-concepts/gateway-registration)
- [应用权限](https://developer.fnnas.com/docs/core-concepts/privilege)
- [util-linux setpriv 官方项目手册](https://man7.org/linux/man-pages/man1/setpriv.1.html)
- [WireGuard 快速开始](https://www.wireguard.com/quickstart/)
- [wgctrl Go 官方项目](https://github.com/WireGuard/wgctrl-go)（控制现有接口，不负责创建接口或配置 IP）

## 0.1.5 端口更新

升级后地址输入框只显示域名/IP。普通端口修改流程：停止 WireGuard 服务 → 修改服务端口 → 保存 → 检测端口 → 启动服务 → 核对顶部实际 UDP 端口 → 重新导出并更新设备配置。路由器端口映射也需与新端口对应，本应用不会自动修改路由器。

如果旧版公网端口与 NAS 监听端口不同，新版会保留差异并勾选“路由器使用不同的公网端口”；若希望两者一致，取消勾选并保存。检测仅检查 NAS 所在网络命名空间的 UDP 端口，不验证公网转发。权限或内核状态不足时明确显示无法检测，不显示假成功。0.1.5 未对 NAS 执行安装、启动、停止或配置写入；只交付本地构建的 FPK。

## 0.1.6 升级与验证

在应用中心手动更新对应架构 FPK。此版本识别默认网关接口的私有 IPv4 家庭网段；需要系统提供 ip、nft、sysctl 和 WireGuard 内核支持。旧默认路由升级为整个家庭网段，保留密钥、端口与设备；旧自定义路由保持自定义模式。

更新后在连接设置核对家庭网段及默认范围，保存并启动服务，再重新导出每个客户端配置，在手机/电脑替换旧配置。设备管理 → 权限可设置独立范围。选定 IP 需要固定地址，探查记录不是在线证明。修改全局范围需先停止 VPN；客户端权限可在运行中更新。

应用启动时开启 IPv4 转发；VPN 开启时配置应用专属 ACL/NAT 与 Docker 转发兼容入口，关闭时清理。不会自动配置路由器映射，也不关闭共享转发开关。NAS 上原有额外防火墙或设备自身防火墙仍可能拒绝访问。

交付前仅在 NAS 执行防火墙检查模式并确认规则未改变；没有安装新版、开关 VPN 或修改 NAS 设置。安装后验收：外网客户端握手、访问 NAS LAN IP/隧道 IP、访问另一台家庭设备、限制客户端仅能访问指定 IP、撤销后既有连接受限、停止后应用规则清理，其他 NAS/Docker 服务正常。跨 VLAN、其他内网子网和 IPv6 LAN 暂不自动管理。

## 0.1.7 防火墙归属兼容修复

实机只读确认 nftables 版本为 1.0.6：`nft -s -a list table inet fnwg_access` 含表归属注释，但 `nft -j list ruleset` 的表对象没有 comment 字段。0.1.6 因此在首次创建后再次保存客户端权限或清理规则时误报归属错误，并可能锁住设备操作。nftables 官方 1.0.6 源码 `src/json.c` 的 `table_print_json` 同样未输出表注释（[官方源码包](https://www.netfilter.org/pub/nftables/nftables-1.0.6.tar.xz)）。

0.1.7 在 JSON 缺少注释时，通过文本表头句柄与表级注释确认归属；不接受链或规则中的同名注释，不接受句柄变化或外部归属。旧版遗留的本应用规则可由新版正常更新、清理，不需要手工删除防火墙表。直接手动更新 FPK，重新打开应用后再保存之前失败的客户端权限；如概览服务未运行，点击启动服务。此次修复不改变客户端导出格式。

测试用真实 NAS 快照调用生产规则生成器，再在 NAS 执行更新、停止两个计划的 `nft --check -f -`，均返回 0，前后静态规则 SHA256 相同。没有安装新版、真正提交防火墙规则、启停 VPN 或修改 NAS 配置。运行时权限执行与外网访问仍需升级后验证。

## 0.1.8 版本检测

“关于”页面按需从 `https://api.github.com/repos/BearHero520/fn-wireguard/releases/latest` 读取公开正式版本。NAS 需要可访问 GitHub；不需要在应用中填写 GitHub 密钥。下载匹配架构的 FPK，在应用中心手动更新，保留已有数据。仅支持检测和下载，不自动安装。错误与检测结果均不会改变 VPN 的运行状态。
