# EIP-7702 批量检测工具

批量检测一组 EOA 是否已被 EIP-7702 授权（Delegated Address）。依据规范：若对某个 EOA 执行 `eth_getCode(<EOA>, latest)` 返回字节码以 `0xef0100` 开头，则被视为已授权；紧随其后的 20 字节即被委托到的合约地址（Delegated Address）。

## 依赖
- Python 3.8+
- 依赖库：`requests`
  - 安装：`pip install requests`

> 注：脚本内部只使用 RPC 方法（Etherscan JSON‑RPC 代理）。

## API Key 配置
- 复制示例文件并填写：
  - `cp .env.example .env`
  - 编辑 `.env`，将 `ETHERSCAN_API_KEY` 设置为你的 Etherscan API Key
- 或者直接在脚本顶部常量 `ETHERSCAN_API_KEY_DEFAULT` 写入密钥。

## CSV 格式要求（重要）
- 输入文件必须是 `CSV`，第一行是表头。
- 第二列为 EOA 地址列（例如列名 `evm_address`）。
- 示例见 `add.csv.example`。

> 当前脚本不会自动检测列位置与表头，仅按上述固定格式读取。

## 使用
1) 准备输入文件（示例见下）。
2) 运行脚本（会覆盖更新原 CSV 文件）：

```
python check_7702_delegation.py -i add.csv
```

运行结束后，脚本会在 CSV 末尾“追加或更新”两列：
- `delegated_address`：若检测到授权，则为被委托的合约地址；否则为空。
- `delegated_flag`：是否检测到授权（1/0）。

## 示例输入（add.csv.example）
参见仓库中的 `add.csv.example`，内容形如：

```
account,evm_address
example1,0x0000000000000000000000000000000000000000
example2,0x0000000000000000000000000000000000000022
```

将其复制为 `add.csv` 后运行脚本即可。

## 速率与稳定性
- 脚本内置请求延时与指数退避，默认约 1.1 秒/请求，批量查询时尽量避免触发限速。
- 如需更高吞吐或支持其它链的 Etherscan 代理域名，可在后续按需扩展脚本（告诉我你的目标链即可）。

## 判定依据（EIP-7702）
- `eth_getCode(<EOA>, latest)` 返回：
  - 以 `0xef0100` 开头：已授权，后续 20 字节即 Delegated Address；
  - 返回 `0x` 或不以该前缀开头：未授权。

参考：EIP-7702 规范 https://eips.ethereum.org/EIPS/eip-7702

