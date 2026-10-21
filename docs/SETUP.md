# 安装、迁移与运行边界

版本：0.1.0 · 2026-10-21

## 先选择用途

如果是讲解方法论，阅读 README、METHODOLOGY 和 PRODUCT 即可。如果要二次开发，先运行离线测试。如果要接真实微信，需要完整的客户端、原生依赖和重新录入流程；本源码导出不能直接复用原机器的账号状态。

## 离线测试

Windows + Python 3.12 x64，先在仓库旁创建隔离环境。以下命令只安装 Python 依赖并执行模拟数据测试，不启动微信发送。

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r deployment/requirements-runtime.txt
$env:NO_PROXY='127.0.0.1,localhost'
$env:PYTHONPATH="$PWD\app;$PWD\app\research"
.\.venv\Scripts\python.exe -m unittest discover -s app -p 'test_*.py'
```

部分原生适配测试还需要兼容的 LIEF；现有生产流程要求 CPython 3.12 x64 的 LIEF 0.12.3 二进制，仓库不携带这个构件。不能因为最新版能够安装，就断言原生接口兼容。测试结果与缺失项见 VALIDATION.md。

## 真实部署前提

路径全部由仓库相对位置或环境变量决定。默认运行依赖目录为仓库 `.runtime`，构建目录为 `.build`，编译器从 PATH 查找。实际微信路径需要自行设置 `MYDEX_WECHAT_DLL` 和 `MYDEX_WECHAT_EXE`；未配置时指向不存在的占位位置，版本校验会拒绝启动。

可覆盖项：`MYDEX_RUNTIME_DIR`、`MYDEX_BUILD_DIR`、`MYDEX_MINHOOK_DIR`、`MYDEX_GCC`、`MYDEX_OBJDUMP`。在同一个环境中运行准备、构建和启动脚本，避免使用不同路径配置。

- 微信 Windows `4.1.15.13`，模块 `Weixin.dll` SHA-256：`10f8e995453e2da46d4f2b5080cd6da1f13cc5147746adc119ceae38cb039de5`。
- Windows 用户本人完成登录；明确授权所需群聊/联系人、历史读取范围和模型服务。
- 原生构件需从版本匹配源码构建、检查哈希并通过独立 fixture 检验。MinHook 源码在 vendor/minhook；v6 发送源在 app/research/worker_sender_v6。

## 推荐迁移顺序

1. 在新目录准备源码、依赖和原生构件；保留原运行目录。
2. 阅读账号录入脚本，确认运行路径及允许会话。示例群号均为占位，不是可直接发送的目标。
3. `deployment/configure_api.py` 在本机录入 API 密钥，DPAPI 加密保存。当前部署模板是特定 Qwen 接口配置；替换供应商时同步调整模板、预检和授权校验。
4. `deployment/enroll_local.py` 实现账号和会话录入；`--observe`、`--finalize`、`--install-sender`、`--prove-sender` 是不同阶段，不可当作普通安装步骤连续盲跑。后两者涉及进程操作/实际发送，需要确认当前机器、账号及测试接收对象。
5. `deployment/preflight.py` 进行只读核验；失败时处理具体缺项，禁止伪造证明文件或移除校验。
6. 完成实机验证后再使用 `deployment/start.ps1`、`status.ps1`、`stop.ps1`。切换前确保同一账号没有两个发送实例。

微信进程变化后，旧 PID、创建时间和发送证明不能继续用。配置完成不等于实际发文/发消息成功；应核对出站记录和接收端。

## 数据保存

私人状态在 `app/.local/` 等运行目录，包括模型密钥、数据库密钥、聊天索引、已绑定账号、消息任务和发送证明。全部排除 Git。模型密钥与 Windows 用户绑定；不同机器迁移应重新录入。源码备份与私人数据备份应分开。

## 构建与兼容性现状

原生源码和第三方许可证已保留；DLL/EXE/PYD 未上传。历史 build.py 的输出路径不完全统一，v6 控制层实际从仓库 `native/worker-sender-v6` 加载，因此构建者必须对照输出路径与清单核验。本次不承诺已完成全新机器上的可重复原生构建。

旧 Frida 动态探针存在已记录的稳定性问题，入口故意禁止运行。该保护已保留。不要把研究目录所有脚本依次执行。
