# Chromecast 遥控器按键句柄归属取证（抓包操作手册）

- 状态：待执行（2026-11-11 起草）。本文件只是操作手册，不是验收记录。
- 适用分支：`chromecast-windows-integration`（`main` 上没有 Chromecast 代码，本手册
  先合入 `main` 只为让各机器都能拿到）。
- 执行环境：已配对 Chromecast Voice Remote（VID `18D1` / PID `9450`）的 Windows 主机，
  装有 Microsoft Bluetooth Virtual Sniffer（`btvs.exe`）与 Wireshark（含 `tshark`）。
- 结果写回：`chromecast-windows-integration` 分支的 `Testing/WindowsChromecast.md`
  新增一节，单独提交。

## 1. 要回答的问题

普通按键在这台主机上"零到达"。现有结论（该分支的 ADR 0004）是：

> 按键通知走空中句柄 `0x0029`，它属于 Google 私有键服务 `{D343BFC0-…}`；Windows 的
> GATT 表在该服务上与空中错位，公开 API 无解。

本手册要验证另一种解释：

> `0x0029` 是 HID 服务（`0x1812`）里 Report ID 1 的输入报告特征。报告已经到了
> Windows 的蓝牙 HID 驱动，只是没有交到应用手里。

提出这种解释的依据：

1. vRemoter 在 macOS 上是从 HID Report 1 读按键的，格式与空中 8 字节一致（首字节
   键码，`0x00` 为松开）。见 `origin/feat/macos-foundation` 分支
   `mac/vremoter/Sources/vRemote/ChromecastRemoteHIDBridge.swift` 的 `handleReport`。
2. Windows 的蓝牙 HID 驱动会自行订阅 HID 报告，应用看不到这个订阅，能解释"没有任何
   应用订阅时遥控器也在发"。
3. 应用查询 `0x1812` 的特征返回 `AccessDenied`，所以应用侧的属性表里本来就看不到
   HID 服务内部的句柄。

两种解释的后续路线完全不同（见第 8 节判定表），所以先取证，不改产品代码。

## 2. 约束

- 只取证：不改产品代码。探针脚本放 `Testing/` 或 `hardware/` 下的 probes 目录。
- 抓包文件含蓝牙地址，**不提交、不贴原始包**。报告里只写句柄、UUID、长度、键码、
  计数。HID 报告描述符（Report Map）不含设备身份，可以贴原始字节。
- 退出 SayAll 走托盘菜单，不强杀（强杀会留下未关闭的 BLE 会话）。
- 每一步写明实际执行的命令和观察到的输出。拿不到的写「未取得」，不推断。
- 结论用仓库的验证词汇：`passed` / `failed` / `deferred`。

## 3. 步骤 1：检查已有抓包里有没有发现阶段

不需要重新抓包。文件：`artifacts/cast-vendor-key-evidence-2026-11-10.pcap`。

先核对本机 tshark 的字段名：

```
tshark -G fields | findstr /i btatt
```

下面命令里的字段名若在本机不存在，改用 `-V` 全量展开对应的包再人工读。

```
:: 1a 主服务发现（Read By Group Type 请求 / 应答）
tshark -r <pcap> -Y "btatt.opcode==0x10 || btatt.opcode==0x11" -V

:: 1b 特征发现（Read By Type 请求 / 应答）
tshark -r <pcap> -Y "btatt.opcode==0x08 || btatt.opcode==0x09" -V

:: 1c 描述符发现（Find Information 请求 / 应答）
tshark -r <pcap> -Y "btatt.opcode==0x04 || btatt.opcode==0x05" -V

:: 1d 全部通知的句柄（逐行输出，人工或用 PowerShell Group-Object 计数）
tshark -r <pcap> -Y "btatt.opcode==0x1b" -T fields -e btatt.handle

:: 1e 全部写请求 / 写命令（找 CCCD 写入）
tshark -r <pcap> -Y "btatt.opcode==0x12 || btatt.opcode==0x52" -T fields -e frame.number -e btatt.handle -e btatt.value
```

记录：

- 1a / 1b / 1c 各有多少个包。
- 三者都是 0：这份抓包没有发现阶段，句柄归属无法从中确定，转步骤 3。
- 有发现包：按第 5 节「要读出的事实」逐条填写，步骤 3 可以不做。

## 4. 步骤 2：WinRT 只读探针

不抓包，只读已配对设备的属性表。用 Rust 测试或 PowerShell 写均可。

1. 用 `BluetoothLEDevice` 打开已配对的 Chromecast 遥控器。
2. `GetGattServicesAsync(BluetoothCacheMode::Cached)` 取全部服务，打印每个服务的
   UUID 与 `AttributeHandle`，按句柄升序排列。
3. 某服务的句柄区间 = 自己的起始句柄，到下一个服务的起始句柄减 1。
4. 对每个服务调用 `GetCharacteristicsAsync(BluetoothCacheMode::Cached)`：
   - 成功：打印每个特征的 UUID、`AttributeHandle`、`CharacteristicProperties`。
   - 失败：记录状态与错误码（HID 服务预期 `AccessDenied`）。
5. `{D343BFC0-…}` 的五个特征必须全部列出，不要只列可通知的那一个。

输出一张表：

| 服务 UUID | 起始句柄 | 推算结束句柄 | 特征数或错误码 |
|---|---|---|---|

注意：`AttributeHandle` 对特征返回的是声明句柄还是值句柄未确认。对照时 `0x0028` 与
`0x0029` 都要看。

判读：

- `0x0029` 落在 `0x1812` 的区间内 ⇒ 支持新解释。
- `0x0029` 落在 `{D343BFC0-…}` 的区间内 ⇒ 支持 ADR 0004。
- 这是 Windows 缓存的属性表，不是空中事实。两者冲突时以步骤 3 的抓包为准。

## 5. 步骤 3：全新配对时抓发现阶段

步骤 1 没有发现包时必须做。这是唯一能拿到权威句柄表的办法：已配对设备重连时
Windows 不再做发现。

操作顺序：

1. 托盘退出 SayAll 预览版，确认进程已结束。
2. 启动抓包：`btvs.exe -Mode Wireshark`，确认 Wireshark 里有包在滚动。
3. 在系统蓝牙设置里删除该遥控器。
4. 遥控器同时按住 返回 + 主页 进入配对；在 Windows 里重新配对，等到显示已连接。
5. **不启动 SayAll**，依次按 确定 ×3、主页 ×3、返回 ×3，每次间隔约 1 秒。
6. 启动 SayAll 预览版并连接。按一次语音键说一句话，松开；再按 确定 ×3。
7. 停止抓包，另存为新文件，不覆盖旧文件。

对新文件重跑步骤 1 的 1a 到 1e，再追加：

```
:: 3a 0x0029 附近的特征声明与描述符
tshark -r <new> -Y "btatt.handle>=0x0026 && btatt.handle<=0x002c" -V

:: 3b Report Reference 描述符（UUID 0x2908）
tshark -r <new> -Y "btatt.uuid16==0x2908" -V

:: 3c Report Map（UUID 0x2A4B），可能分多段 Read Blob
tshark -r <new> -Y "btatt.uuid16==0x2a4b || btatt.opcode==0x0c || btatt.opcode==0x0d" -V

:: 3d 0x0029 上的通知
tshark -r <new> -Y "btatt.opcode==0x1b && btatt.handle==0x0029" -T fields -e frame.time_relative -e btatt.value
```

要读出的事实：

1. 每个主服务的 UUID、起始句柄、结束句柄（完整列表）。
2. 值句柄为 `0x0029` 的特征：UUID、属性位、所属服务。
3. `0x002A` 是不是它的 CCCD；谁在什么时刻往里写了什么值。重点看第 5 步之前
   （SayAll 未运行时）有没有写入。
4. 它的 Report Reference 值。`01 01` 表示 Report ID 1、输入报告。
5. Report Map 的原始字节。据此算出 Report ID 1 声明的长度，对比空中实际的 8 字节。
6. 第 5 步（SayAll 未运行）期间 `0x0029` 的通知数；第 6 步期间的通知数。
7. 每条通知的长度与首字节（键码）。键码对照：1=电源、3=上、4=下、5=左、6=右、
   7=确定、8=静音、10=主页、11=返回、12=音量+、13=音量−、14=YouTube、15=Netflix、
   17=输入源。

## 6. 步骤 4：Windows HID 层看到了什么

对 VID `18D1` / PID `9450` 的设备，枚举它的**全部**顶层集合，不只是 Consumer
Control：

- 每个集合的 usage page、usage、`InputReportByteLength`。
- 每个集合用 `HidP_GetButtonCaps` / `HidP_GetValueCaps` 列出的输入 Report ID 与
  各自的位长。

目的：

- 确认 Report ID 1 属于哪个集合、Windows 认为它多长。
- 确认有没有厂商自定义页的集合。应用的 Raw Input 目前只注册了键盘
  （`0x01` / `0x06`）与消费页（`0x0C` / `0x01`）两类；若按键报告落在未注册的集合，
  改注册即可，不需要提权助手。

## 7. 步骤 5：在驱动宿主进程内只观察

**前置条件**：步骤 2 或步骤 3 已证明 `0x0029` 在 HID 服务内。否则不做。需要管理员
权限。

用现有 helper 附加到承载该遥控器的 `WUDFHost.exe`，agent 以只观察模式运行：

- 对 `IOCTL 0x80018483` 的每次完成，只记录输出长度、首字节、第二字节。
- 不清零、不改写、不上报 edge。
- 现有 agent 只接受 `[0x02, 低, 高]` 的 3 字节报告与 RC003 的 9 字节报告，本步骤要
  记录**所有**形态，不要沿用这个过滤。

操作：按 确定 ×3、主页 ×3。

记录：出现了哪些「首字节 + 长度」组合，各多少次。一次都没有就如实记零。

## 8. 判定表

| 观察结果 | 结论 | 下一步 |
|---|---|---|
| `0x0029` 在 `0x1812` 区间内，Report Reference 为 ID 1 输入 | 按键走标准 HID，问题在 Windows HID 层没有上交；ADR 0004 的"属性表错位"结论撤回 | 做步骤 4、步骤 5 |
| 上一条成立，且步骤 4 发现 Report 1 在未注册的集合里 | 不需要助手 | 应用补注册该集合的 Raw Input |
| 上一条成立，且步骤 5 看到首字节 `0x01` 的报告 | 报告层助手可行 | agent 增加「Report 1、首字节键码」报告类，复用现有键码表 |
| `0x0029` 在 `0x1812` 内，但步骤 5 计数为零 | 报告在到达 `WUDFHost.exe` 之前就丢了 | 另行调查，不动助手 |
| `0x0029` 在 `{D343BFC0-…}` 区间内 | ADR 0004 结论成立 | 换一台 Windows 主机复现 |

## 9. 交付格式

在 `chromecast-windows-integration` 分支的 `Testing/WindowsChromecast.md` 新增一节
「按键句柄归属取证（日期）」，内容：

1. 环境：Windows 版本号、遥控器固件版本、预览版 `source_revision`、btvs 与 tshark
   版本。
2. 按步骤编号列出：执行的命令、关键输出（脱敏）、该步结论。
3. 第 5 节的七条事实逐条填写。
4. 对照第 8 节判定表给出命中的那一行。
5. 未取得或未执行的步骤标 `deferred` 并写明原因。

单独提交，不与代码改动混在一起。
