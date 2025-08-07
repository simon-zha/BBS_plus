# BBS+ Threshold Signature Implementation

一个基于椭圆曲线密码学的BBS+阈值签名算法实现，支持基础签名、阈值签名和盲签名功能。

## 📋 功能特性

- **基础BBS+签名**: 支持向量消息的数字签名
- **阈值签名**: 分布式签名，需要t个参与方协作生成有效签名  
- **盲签名**: 弱部分盲签名，保护消息隐私
- **网络通信**: 基于TCP/IP的客户端-服务器架构
- **椭圆曲线**: 使用BLS12-381曲线和双线性配对
- **性能测试**: 内置基准测试工具

## 🗂️ 项目结构

```
new_bbs_plus/
├── bbs/                    # 核心算法实现
│   ├── bbs_plus.py        # BBS+签名算法
│   ├── threshold.py       # 阈值签名和盲签名
│   ├── curve.py           # 椭圆曲线运算
│   └── commitment.py      # 承诺机制
├── test/                   # 测试和示例
│   ├── server.py          # 阈值签名服务器
│   └── client.py          # 测试客户端
├── benchmark/              # 性能测试
│   └── benchmark.py       # 基准测试工具
└── README.md              # 项目文档
```

## 🔧 安装要求

### 依赖库

```bash
pip install py_ecc
```

### Python版本
- Python 3.7+

## 🚀 快速开始

### 1. 基础测试

运行本地测试验证所有功能：

```bash
cd new_bbs_plus
python test/simple_local_test.py
```

### 2. 阈值签名网络测试

启动4个服务器实例：

```bash
# 终端1
python test/server.py --id 1 --port 8001

# 终端2  
python test/server.py --id 2 --port 8002

# 终端3
python test/server.py --id 3 --port 8003

# 终端4
python test/server.py --id 4 --port 8004
```

运行客户端测试：

```bash
# 终端5
python test/client.py
```

### 3. 性能基准测试

```bash
python benchmark/benchmark.py
```

## 📊 测试流程

客户端会依次测试以下功能：

1. **系统初始化**: 设置公钥和密钥分享
2. **基础阈值签名**: 生成和验证阈值签名
3. **简化盲签名**: 测试基本盲签名流程
4. **正式盲签名**: 使用完整的论文协议
5. **签名验证**: 验证所有生成的签名

### 预期输出

```
BBS+ Threshold Signature Test
Ports: [8001, 8002, 8003, 8004], Threshold: 3, Messages: [111, 222, 333]

--- Init ---
Setup server 8001
Got public key from 8001
Server 8001 OK
...
System ready (4/4)

--- Sign ---
Signing: [111, 222, 333]
Getting partial sig from 8001
Got partial from 8001
...
Signature ready

--- Verify ---
Verifying...
Verify: PASS

--- Blind Signature Test ---
Testing blind signature...
Blind signature generated
Blind signature verify: PASS

--- Formal Blind Signature Test ---
Testing FORMAL blind signature...
Formal blind signature generated
Formal blind signature verify: PASS

--- Result ---
SUCCESS: Threshold signature works!
SUCCESS: Blind signature also works!
SUCCESS: Formal blind signature works!
```

## 🔬 技术细节

### 算法参数

- **椭圆曲线**: BLS12-381
- **参与方数量**: n = 4
- **阈值**: t = 3  
- **消息长度**: 支持任意长度的向量消息

### 密钥分享

使用Shamir秘密分享方案：
- 秘密密钥分割为n份
- 任意t份可重构原始密钥
- 拉格朗日插值重构

### 盲签名机制

支持弱部分盲签名：
- **公开信息**: 签名方可见
- **私有信息**: 经过盲化保护
- **盲化参数**: `blinding_nonce_e`, `blinding_nonce_s`

### 网络协议

基于JSON的简单协议：

```json
// 系统初始化
{"type": "setup", "message_length": 3, "threshold": 3}

// 阈值签名
{"type": "sign", "messages": [111, 222, 333], "threshold": 3}

// 签名组合
{"type": "combine", "partial_signatures": [...], "messages": [...]}

// 盲签名
{"type": "blind_sign", "messages": [...], "public_info": [...], "private_info": [...]}
```

## 📈 性能基准

基准测试包含：

1. **椭圆曲线运算**
   - G1标量乘法
   - G2标量乘法  
   - 双线性配对

2. **密钥生成**
   - 不同消息长度的setup时间

3. **签名生成**
   - 完整阈值签名流程
   - 多轮通信时间

4. **签名验证**
   - 单签名验证
   - 批量验证

## 🔒 安全特性

- **抗伪造**: 基于双线性配对的困难问题
- **阈值安全**: 需要t个诚实参与方
- **盲签名隐私**: 私有消息对签名方不可见
- **零知识**: 承诺机制保护中间值

## 📚 文件说明

### 核心算法

- **`bbs/bbs_plus.py`**: BBS+签名的基本实现
  - `gen()`: 密钥生成
  - `sign()`: 签名生成
  - `verify()`: 签名验证

- **`bbs/threshold.py`**: 阈值和盲签名实现
  - `ThresholdBBSPlus`: 简化阈值签名
  - `FormalThresholdBBSPlus`: 完整论文协议
  - `WeakPartiallyBlindSigning`: 盲签名机制

- **`bbs/curve.py`**: 椭圆曲线运算
  - BLS12-381曲线操作
  - 点序列化/反序列化
  - 双线性配对

### 网络组件

- **`test/server.py`**: 阈值签名服务器
  - 支持多种签名协议
  - 多线程处理
  - 确定性setup

- **`test/client.py`**: 测试客户端
  - 完整测试流程
  - 多种签名测试
  - 错误处理

## 🛠️ 开发说明

### 添加新功能

1. 在`bbs/`目录添加新算法
2. 在`test/`目录添加测试
3. 更新服务器请求处理
4. 添加客户端调用接口

### 调试建议

- 使用`simple_local_test.py`快速验证算法
- 检查服务器日志排查网络问题
- 启用详细输出调试协议流程

## 📖 参考文献

- BBS+ Signatures: [原始论文链接]
- 阈值签名协议: [协议4.1描述]
- BLS12-381曲线: [曲线规范]

## 🤝 贡献

欢迎提交Issue和Pull Request来改进项目。

## 📄 许可证

本项目仅供学习和研究使用。