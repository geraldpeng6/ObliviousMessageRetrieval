# OMR 项目代码架构与“通信”机制分析

## 1. 项目架构总览：一个本地模拟程序

经过对 `main.cpp` 及相关代码的深入分析，可以明确本项目是一个**本地的、单进程的密码学模拟程序**，而非一个包含真实网络通信的客户端/服务器（C/S）应用。

项目中提到的“客户端”和“服务器”是**概念上的角色**，分别由不同的函数集合在同一个程序中实现。它们之间的“通信”是通过**直接的 C++ 函数调用**来完成的，数据（如 `seal::Ciphertext` 密文对象）通过函数参数和返回值在内存中直接传递。

整个项目的目的是为了**验证和评测 OMR 方案的密码学性能**（如计算耗时、密钥/密文大小），而不是为了演示一个可部署的网络服务。

---

## 2. 核心角色与对应函数分析

代码的业务逻辑主要围绕两个核心角色展开：**接收者 (Recipient)**，即客户端；**探测器 (Detector)**，即服务器。

### 2.1 “服务器” (Detector) 的功能实现

“服务器”的角色负责执行计算密集型的同态加密操作。这些功能主要由以下函数承担：

*   `serverOperations1obtainPackedSIC(...)`:
    *   **功能**: 执行 OMR 协议的第一阶段。它接收客户端的“密文线索”（`PVWCiphertext`），并利用“密文转换密钥”（`switchingKey`）进行计算，最终输出一个打包好的、包含所有消息处理结果的密文（`packedSIC`）。
    *   **作用**: 这是探测阶段的核心，用于判断哪些消息是目标消息。

*   `serverOperations2therest(...)` 和 `serverOperations3therest(...)`:
    *   **功能**: 执行 OMR 协议的第二阶段，即消息内容的检索。它们接收第一阶段的结果（`packedSIC`），并根据预设的“二部图”和权重信息，对数据库中的载荷（`payload`）进行同态乘法和加法，最终分别生成用于索引恢复的密文（`lhs`）和内容恢复的密文（`rhs`）。
    *   **区别**: `serverOperations2therest` 用于确定性 OMR，而 `serverOperations3therest` 用于随机性 OMR。
    *   **作用**: 这是检索阶段的核心，负责安全地提取出目标消息内容。

### 2.2 “客户端” (Recipient) 的功能实现

“客户端”的角色负责生成密钥、准备查询数据、以及在收到“服务器”的处理结果后进行解密和解码。这些功能主要由以下函数承担：

*   `preparinngTransactionsFormal(...)`:
    *   **功能**: 模拟一个拥有“目标消息”的数据库环境。它会生成一批消息，其中一部分被标记为“目标消息”，并为所有消息生成加密线索（Clues），这些线索将被“服务器”读取。
    *   **作用**: 准备整个模拟实验的输入数据。

*   `receiverDecoding(...)` 和 `receiverDecodingOMR3(...)`:
    *   **功能**: 这是客户端最关键的解码步骤。它接收从“服务器”函数返回的加密结果（`lhsEnc` 和 `rhsEnc`），使用只有自己知道的 `secret_key` 进行解密，并执行一系列解码操作（如 `decodeIndices`、`formRhs`、`formLhsWeights` 和 `equationSolving`）来恢复出原始消息的索引和内容。
    *   **作用**: 完成 OMR 流程的最后一步，从加密的“大杂烩”中提取出自己想要的信息。

---

## 3. “通信”机制：直接函数调用

如前所述，本项目没有网络通信。下面我们以 `OMR2()` 函数为例，展示“客户端”和“服务器”是如何通过函数调用链进行交互的：

```cpp
void OMR2() {
    // === 1. 客户端准备阶段 ===
    // 生成各类密钥和参数 (secret_key, public_key, etc.)
    auto params = PVWParam(...);
    auto sk = PVWGenerateSecretKey(params);
    auto pk = PVWGeneratePublicKey(params, sk);

    // 客户端准备好所有消息和“线索”，并保存到文件中（模拟发送给服务器）
    auto expected = preparinngTransactionsFormal(pk, ...);

    // 客户端生成“密文转换密钥”，这是查询的关键
    genSwitchingKeyPVWPacked(switchingKey, ...);

    // === 2. 服务器处理阶段 ===
    // 服务器通过调用 serverOperations1obtainPackedSIC，处理所有消息线索
    // 这是一个循环，分批处理所有消息
    for (/* each batch */) {
        loadClues(...); // 从文件加载“客户端”准备的线索
        packedSICfromPhase1[i][j] = serverOperations1obtainPackedSIC(...);
    }

    // 服务器继续调用 serverOperations2therest，处理消息内容
    for (/* each batch */) {
        loadData(...); // 加载数据库内容
        serverOperations2therest(templhs, ..., temprhs, ...); // 执行同态计算
        // 将每批次的结果累加起来
        evaluator.add_inplace(lhs_multi[i], templhs);
        evaluator.add_inplace(rhs_multi[i], temprhs);
    }

    // === 3. 客户端解码阶段 ===
    // 服务器的所有计算结果 (lhs_multi[0], rhs_multi[0]) 被直接传递给客户端的解码函数
    auto res = receiverDecoding(lhs_multi[0], ..., rhs_multi[0], ..., secret_key, ...);

    // === 4. 结果验证 ===
    if(checkRes(expected, res)) {
        cout << "Result is correct!" << endl;
    }
}
```

**交互流程总结**：
1.  **初始化**：`OMR2()` 函数首先扮演“客户端”角色，生成所有必需的密钥和参数。
2.  **查询准备**：它调用 `preparinngTransactionsFormal` 准备好“消息”和“线索”，并调用 `genSwitchingKeyPVWPacked` 生成查询密钥。
3.  **服务器计算**：`OMR2()` 接着扮演“服务器”角色，通过循环调用 `serverOperations1obtainPackedSIC` 和 `serverOperations2therest` 来处理数据。数据（如线索、载荷）是通过 `loadClues` 和 `loadData` 从本地文件系统加载的，这模拟了服务器访问其数据库的过程。
4.  **解码**：`OMR2()` 最后再次扮演“客户端”角色，将上一步计算得到的密文结果和 `secret_key` 一起传递给 `receiverDecoding` 函数，恢复出明文结果。

---

## 4. `main()` 函数：实验的总控制器

`main()` 函数是整个程序的入口。它提供了一个简单的命令行菜单，让用户可以选择运行不同的 OMR 方案（`OMD1p`, `OMR2p`, `OMR3p`）或不同的线程数配置。

它的核心作用就是根据用户的输入，调用 `OMR2()` 或 `OMR3()` 等顶层控制函数，启动一次完整的本地模拟流程。它本身不包含任何密码学逻辑，仅仅是一个**实验的启动器和协调器**。
