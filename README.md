# 飞牛 WireGuard

作者：[BearHero520](https://github.com/BearHero520) · [GitHub 项目](https://github.com/BearHero520/fn-wireguard) · [下载安装包](https://github.com/BearHero520/fn-wireguard/releases/latest)

面向飞牛 NAS 的 WireGuard 服务端管理工具。Go + SQLite 后端，React + TypeScript + Vite 8 前端，原生 FPK 安装包。

界面使用中文、iOS 18 磨砂质感与 Element Plus 主题蓝，采用用户选定的「蓝调控制台」布局。Element Plus 是视觉参考，前端没有混入 Vue。

## 已实现的范围

- 总览：服务运行状态、真实近期握手、设备数量和流量计数。
- 设备管理：添加、改名、停用、删除，生成独立密钥与虚拟地址。
- 配置交付：明确操作后显示 WireGuard 二维码、复制或下载 `.conf`。
- 配置导入：读取 `.conf` 文件或粘贴内容，先校验和预览，再确认应用。
- 连接设置：公网地址、UDP 端口、虚拟网段、DNS、默认局域网访问范围。
- 访问权限：默认整个家庭 IPv4 网段；每个客户端可跟随默认、访问整个网段，或只访问指定设备。
- 局域网发现：读取邻居记录，手动探查 NAS 所在网段并勾选设备，也可添加固定 IP。
- 自动 DNS：沿用手机或电脑当前网络，保留手动指定选项。只填域名或 IP 时自动补齐监听端口。
- 操作日志：记录配置和设备变更，不记录私钥或导出的完整配置。
- 原生入口：飞牛统一网关管理员鉴权；本地开发使用独立管理员登录。
- 关于应用：作者与版本信息、GitHub 项目入口、手动检测正式版本及匹配 NAS 架构的安装包下载。

这是供自行安装验证的首版项目，不代表已经通过飞牛应用中心上架审核。

服务端配置导入适合迁移到空实例，要求服务已停止且没有现有设备；设备配置导入则要求对端公钥匹配当前 NAS。服务端 `.conf` 不包含各设备私钥，导入后这些设备仍可使用原配置连接，但只有补充匹配的设备配置后才能重新导出客户端配置。服务端导出仅包含已启用的设备，不等于完整数据备份。

## 本地运行

需要 Node.js 22.12+ 或较新 LTS、支持自动工具链的 Go，以及 npm。项目锁定 Vite 8，依赖精确安装使用 `npm ci`。

```powershell
cd web
npm ci
npm run build
cd ..
go run ./cmd/fn-wireguard --data-dir .local/data --web-dir web/dist --mode development
```

打开 [本地管理页](http://127.0.0.1:8787)。首次初始化时，从 `.local/data/bootstrap-token` 读取安装令牌并在网页设置管理员；初始化成功后令牌文件被删除。密码至少 12 字节。不要将本地开发数据目录上传到版本库。

Windows 开发模式可以完成设备管理、配置生成与界面调试，但不启动 WireGuard 接口，界面会明确显示这一点。开发热更新可在 `web` 中运行 `npm run dev`，后端继续监听 8787。

## 构建飞牛安装包

```powershell
./scripts/build-fpk.ps1 -Architecture amd64
./scripts/build-fpk.ps1 -Architecture arm64
```

脚本调用官方 fnpack，按架构生成 `dist/fn-wireguard-amd64.fpk` 或 `dist/fn-wireguard-arm64.fpk`。在飞牛应用中心使用手动安装；最低系统要求、权限和真机验收步骤见 [飞牛部署说明](docs/FNOS.md)。

## 安全和网络范围

设备私钥与预共享密钥使用 AES-256-GCM 加密入库，主密钥单独保存在应用私有目录；SQLite 文件不是整体加密数据库。备份必须一起保护数据库与主密钥。管理页面支持飞牛 HTTP 和 HTTPS 入口，不强制 HTTPS；HTTP 适合可信局域网，推荐 HTTPS 保护管理会话与导出的配置。WireGuard 隧道加密不会为 HTTP 管理页面加密。

二维码和导出的配置含设备私钥，应当只交给对应设备持有人。不要把管理页直接暴露到公网。需要开放给远程客户端的是 WireGuard 的 UDP 端口。

0.1.6 默认识别 NAS 默认网关所在的家庭 IPv4 网段，为专用 `fnwg0` 接口生成客户端路由、服务端访问控制与 NAT。保持 NAS 默认路由、系统 DNS 和路由器端口映射不变。应用启动时开启共享 IPv4 转发，停止时不关闭它；VPN 停止时只清理本应用标记的规则。旧版自行配置的 AllowedIPs 保留为“自定义路由”，该模式不自动配置转发权限。

“在线”表示最近 3 分钟有握手，是近期活动提示，不是持续连通性证明。流量计数来自内核，接口重建后可能清零。

## 验证

```powershell
go test ./...
go vet ./...
cd web
npm test
npm run build
cd ..
go build -o .local/fn-wireguard.exe ./cmd/fn-wireguard
python scripts/smoke-test.py --binary .local/fn-wireguard.exe
python scripts/import-smoke.py --binary .local/fn-wireguard.exe
python scripts/lifecycle-smoke.py
```

集成验证只使用独立临时开发数据库，不修改主机网络。它覆盖初始化、鉴权、CSRF、输入校验、设备变更、加密存储、配置导出及进程重启后的持久性。导入验证使用两个隔离实例，检查迁移、私钥补全、配置往返，以及令牌重放、跨会话、状态变化和危险配置拒绝。真实的 NAS 安装、网关转发与手机握手需要在飞牛设备上单独验证。

生命周期回归需要 Bash（Windows 可用 Git Bash），执行实际脚本并模拟旧应用文件与新升级脚本并存的阶段。测试替身不验证真实 Linux 权限或 WireGuard 内核行为。

架构与验收责任见 [ARCHITECTURE.md](docs/ARCHITECTURE.md)，界面参考与生成提示词见 [design/README.md](design/README.md)。

本次验证使用 Go 1.26.8：Go 测试、静态检查、前端构建、6 组基础 HTTP 集成检查和 14 项导入导出检查通过。双架构 FPK 已核对 Linux 可执行权限、ELF 架构、脚本语法、manifest 校验值及前端资源一致性。界面验收记录见 [design-qa.md](design-qa.md)。

0.1.4 增加地址保存与自动 DNS 回归，HTTP 集成检查扩展至 7 组；覆盖飞牛网关去除 Host 端口时的保存和启动请求，以及非法来源、无会话、非管理员、错误 CSRF 和 UID 不匹配的拒绝。背景采用用户提供的 `MIUI9_wallpaper_02.jpg` 蓝绿渐变，保留磨砂面板及蓝色交互主题。

2026-09-30 的 govulncheck Linux 目标源码扫描未发现实际调用或导入包的已知漏洞；依赖模块 `golang.org/x/crypto` 仍有未使用的 OpenPGP 告警 GO-2026-5932。二进制扫描也报告此告警，因此这里不宣称所有扫描均为零告警。

## 官方参考

- [飞牛 Native 应用开发](https://developer.fnnas.com/docs/examples/native)
- [飞牛统一网关](https://developer.fnnas.com/docs/core-concepts/gateway-registration)
- [WireGuard Quick Start](https://www.wireguard.com/quickstart/)
- [Vite 8](https://vite.dev/blog/announcing-vite8)
- [Element Plus 主题变量](https://element-plus.org/en-US/guide/theming)

## 0.1.5：端口同步与检测

公网连接地址输入框仅填写域名或 IP，服务端口独立填写。默认将同一个端口用于 NAS 监听和客户端连接，修改、保存后重新导出客户端配置即可获得新端口。服务启动使用已保存设置；有未保存更改时会提示先保存。路由器公网端口与 NAS 端口不同时，可勾选“路由器使用不同的公网端口”单独设置；旧版已有不同端口的配置会保留，并在该选项中明确显示。

“检测端口”检查指定 NAS UDP 端口，区分本应用已生效、当前空闲、其他 UDP 监听占用和无法检测。检查同时覆盖 IPv4/IPv6，不把同号 TCP 监听算作冲突。检测只代表当时状态，不预留端口，不验证路由器映射或公网可达性。启动/应用配置后会读取 WireGuard 内核配置核对监听端口；总览显示实际端口，发现保存值与实际值不同时提示重新启动。接口存在但未启用时不再显示运行中。

页面使用 4px 悬浮滚动条，不占页面布局宽度，支持拖动、键盘与滚轮；弹窗、配置预览等内层滚动区域采用细滚动条。触屏及系统高对比度模式保留原生滚动条。

0.1.5 验证：4 组前端端口转换回归、Go 测试及 vet、8 组真实 HTTP 集成、14 项导入导出检查、桌面与 390px 手机布局检查通过。真实 NAS 安装和 WireGuard 握手尚待安装后验证。

## 0.1.6：局域网访问与界面交互

旧版默认的“仅隧道网段”配置升级为整个家庭局域网，已有密钥、设备、公网地址和端口保留。客户端需重新导出并导入配置才能获得家庭网段路由。全局访问范围变更前停止 VPN；单客户端权限支持运行时保存并在失败时回滚。指定设备使用 IP 控制，建议通过 DHCP 固定地址；不等同于按 MAC 认证。

连接设置可选择整个家庭网段或指定 IP，设备管理的“权限”允许独立覆盖默认设置。允许 NAS 时同时允许其隧道地址及已发布的容器端口；未选择 NAS 的客户端不会隐式获得 NAS 服务访问。仅支持主家庭 IPv4 网段，不包含跨 VLAN、其他子网、IPv6 内网或互联网出口。

探查最多覆盖 NAS 所在 /24 的 254 个地址（原子网更小时使用原子网），最多 24 个并发单端口 TCP 连接尝试、6 秒截止、10 秒冷却。没有应用层探测或任意网段扫描。邻居记录不表示在线；未响应的设备可手动添加。

复制配置在弹窗内部提示成功并显示“已复制”；全局隐藏滚动条，保留滚动操作。页面切换淡入、按钮与选项提供短动画，遵循系统减少动态效果设置。设备操作菜单点击外部、Escape、滚动或切页后收起；主卡片、步骤卡与选项卡片统一 16px 间距。

验证包括 Go 测试、vet、真实本地 HTTP/导入回归、生命周期脚本模拟及桌面/手机浏览器检查。NAS 上仅执行 `nft --check` 并比较检查前后规则，未部署或改动 NAS；实际 VPN 到家庭设备的通信仍需安装后验证。

## 0.1.7：客户端权限保存修复

修复飞牛 NAS 的 nftables 1.0.6 在 JSON 输出中缺少表注释、导致本应用误报“防火墙表不属于本应用”的兼容问题。缺少 JSON 标记时，读取文本输出核对表头、表句柄和紧随表头的归属注释；其他应用的同名表仍拒绝操作。删除使用已核实的句柄，新建使用排他创建，防止读取之后出现同名表替换。

只读检查失败时不再发起无意义的回滚；更新失败但旧配置已恢复时不再锁住后续设备操作。真正回滚失败仍要求成功停止或重新启动服务。相关提示改为中文，防火墙具体错误写入应用日志。

使用应用中心直接更新 0.1.7，无需卸载或重新创建设备。密钥、地址、端口和已保存权限保留；之前报错的权限未保存，升级后重新设置。验证覆盖旧版 JSON 读回、连续权限更新及停止、外部表拒绝、失败重试和回滚失败保护。已使用目标 NAS 实际规则快照生成更新与清理计划，两项 `nft --check` 通过，检查前后规则摘要一致；未在 NAS 安装新版或更改运行状态。

## 0.1.8：关于与更新检测

作者与维护者为 [BearHero520](https://github.com/BearHero520)。关于页面显示当前版本和运行架构，可手动检测本仓库的 GitHub 正式发布版。下载适配架构的 FPK 后，进入飞牛应用中心手动更新。应用不执行自动安装。

更新检测复用管理员会话与 CSRF 验证，仅请求固定 GitHub Releases API；不传输密钥、设备列表或配置。成功结果缓存 5 分钟，失败结果缓存 30 秒；网络请求最多等待 8 秒，不阻塞服务启停。暂未发布版本、网络故障和请求限流会分别提示。官方接口说明见 [GitHub Releases API](https://docs.github.com/en/rest/releases/releases#get-the-latest-release)。

发布时同时修改 `internal/buildinfo/info.go` 与 `packaging/fnos/manifest` 的版本；构建会检查两者一致。GitHub Tag 使用 `vX.Y.Z`，Release 安装包命名为 `fn-wireguard-X.Y.Z-amd64.fpk` / `fn-wireguard-X.Y.Z-arm64.fpk`，确保应用可匹配下载。正式发布包和 SHA256 校验值放在 GitHub Releases，源码仓库不包含本地数据和诊断文件。
