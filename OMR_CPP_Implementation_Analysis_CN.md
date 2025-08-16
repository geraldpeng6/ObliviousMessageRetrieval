# OMR库 C++ 实现深度解析与性能评测指南

## 1. 引言

本文档是 `OMR_Library_Intro_CN.md` 的进阶篇，旨在为开发者提供一份关于本 OMR 库 C++ 实现的深度技术指南。我们将深入探讨代码层面的具体实现、项目结构、以及如何对该方案进行科学的性能评测。

阅读本文档前，我们假定您已经具备基础的 C++ 知识，并对 OMR 的基本原理有所了解。

---

## 2. 代码结构解析

一个典型的 OMR C++ 项目通常会遵循以下结构，以便于模块化开发和维护：

```
omr-library/
├── src/
│   ├── client.cpp          # 客户端逻辑实现
│   ├── server.cpp          # 服务器端逻辑实现
│   ├── common/
│   │   ├── crypto.cpp      # 封装核心密码学操作（HE, RLC）
│   │   └── types.cpp       # 定义通用数据结构
│   └── main.cpp            # 演示程序入口
├── include/
│   ├── client.h
│   ├── server.h
│   ├── common/
│   │   ├── crypto.h
│   │   └── types.h
├── benchmark/
│   ├── benchmark.cpp       # 性能评测程序
│   └── plotting/           # 存放性能图表和绘图脚本
└── CMakeLists.txt          # 项目构建配置
```

*   **`src/` 和 `include/`**: 存放所有核心逻辑的源代码和头文件。
    *   `client.h/.cpp`: 定义并实现 `OMRClient` 类。它负责管理用户密钥、生成检测/检索请求、以及解密从服务器返回的响应。
    *   `server.h/.cpp`: 定义并实现 `OMRServer` 类。它负责加载和管理消息数据库、处理客户端请求并返回响应。
    *   `common/crypto.h/.cpp`: **项目的技术核心**。它封装了与底层密码学库（如 Microsoft SEAL）的交互。例如，`CryptoProvider` 类会负责初始化同态加密（HE）参数、提供加密、解密、同态求值等接口。
    *   `common/types.h/.cpp`: 定义项目中的通用数据结构，例如 `Message`, `DetectionRequest`, `RetrievalResponse` 等，方便序列化和网络传输。
*   **`benchmark/`**: 存放性能测试相关代码。`benchmark.cpp` 通常是一个独立的、可配置的程序，用于在不同参数下运行 OMR 协议并测量性能。
*   **`CMakeLists.txt`**: CMake 构建文件，定义了项目的依赖项、编译目标和链接规则。

---

## 3. 核心流程的 C++ 实现

下面我们通过 C++ 伪代码来剖析 OMR 协议两个核心阶段的实现细节。

### 3.1 初始化阶段

在通信开始前，客户端和服务器都需要初始化各自的密码学环境。

**客户端 `OMRClient::initialize()`**
```cpp
// include/client.h
#include "common/crypto.h"

class OMRClient {
public:
    void initialize();
    // ...
private:
    std::unique_ptr<CryptoProvider> crypto_provider_;
    SecretKey he_sk_;
    PublicKey he_pk_;
};

// src/client.cpp
void OMRClient::initialize() {
    // 1. 创建并配置 CryptoProvider
    crypto_provider_ = std::make_unique<CryptoProvider>(/* security_level */ 128);

    // 2. 生成同态加密的公私钥对
    auto key_pair = crypto_provider_->generate_keys();
    he_sk_ = key_pair.secret_key;
    he_pk_ = key_pair.public_key;

    // 3. 将公钥发送给服务器（带外传输）
    // send_public_key_to_server(he_pk_);
}
```

**服务器 `OMRServer::initialize()`**
```cpp
// src/server.cpp
void OMRServer::initialize(const PublicKey& client_pk) {
    // 1. 从客户端获取公钥并初始化 CryptoProvider
    crypto_provider_ = std::make_unique<CryptoProvider>(/* security_level */ 128);
    crypto_provider_->set_public_key(client_pk);

    // 2. 加载消息数据库
    // this->database_ = load_messages_from_disk();
    // 假设 database_ 是一个 std::vector<Message>
}
```

### 3.2 消息检测阶段 (RLC)

此阶段的目标是快速判断服务器上是否**可能**有客户端的消息。

**客户端 `OMRClient::generate_detection_request()`**
```cpp
// src/client.cpp
DetectionRequest OMRClient::generate_detection_request(uint64_t message_index) {
    // 1. 获取与消息索引相关的 RLC 种子
    auto seed = generate_seed_for_index(message_index);

    // 2. 使用种子生成一个稀疏向量 (sparse vector)
    auto sparse_vector = crypto_provider_->generate_rlc_vector(seed);

    DetectionRequest req;
    req.query = sparse_vector; // 伪代码，实际可能是某种特定格式
    return req;
}
```

**服务器 `OMRServer::handle_detection_request()`**
```cpp
// src/server.cpp
DetectionResponse OMRServer::handle_detection_request(const DetectionRequest& req) {
    // 1. 准备一个零向量用于累加
    auto result_vector = crypto_provider_->create_empty_vector();

    // 2. 遍历数据库中的所有消息
    for (size_t i = 0; i < database_.size(); ++i) {
        // 2a. 获取该消息的 RLC 编码
        auto message_seed = generate_seed_for_index(i);
        auto message_rlc_code = crypto_provider_->generate_rlc_vector(message_seed);

        // 2b. 将其与请求向量进行某种形式的“点积”或“乘法”
        // 这一步非常快，通常是基于 XOR 的操作
        auto processed_code = crypto_provider_->process_vector_with_query(message_rlc_code, req.query);

        // 2c. 累加结果
        result_vector.add(processed_code);
    }

    DetectionResponse resp;
    resp.hint = result_vector;
    return resp;
}
```

### 3.3 消息检索阶段 (HE)

当检测成功后，客户端发起真正的检索请求。

**客户端 `OMRClient::generate_retrieval_request()`**
```cpp
// src/client.cpp
RetrievalRequest OMRClient::generate_retrieval_request(uint64_t target_index, uint32_t db_size) {
    // 1. 创建一个明文选择向量 (selection vector)
    // 这是一个长度为 db_size 的向量，目标索引位置为 1，其余为 0
    std::vector<int64_t> selection_vector(db_size, 0);
    selection_vector[target_index] = 1;

    // 2. 加密这个选择向量
    Plaintext pt = crypto_provider_->encode(selection_vector);
    Ciphertext ct = crypto_provider_->encrypt(pt, he_pk_); // 使用公钥加密

    RetrievalRequest req;
    req.encrypted_query = ct;
    return req;
}
```

**服务器 `OMRServer::handle_retrieval_request()` (使用 SEAL 风格 API)**
```cpp
// src/server.cpp
// 假设 crypto_provider_ 内部持有一个 std::shared_ptr<seal::SEALContext> context;
// 和一个 seal::Evaluator evaluator;

RetrievalResponse OMRServer::handle_retrieval_request(const RetrievalRequest& req) {
    // 1. 将整个消息数据库编码为多个 seal::Plaintext
    //    为提高效率，通常会将多个消息打包到一个Plaintext中（Batching）
    //    这里为清晰起见，假设一个Plaintext对应一个消息。
    std::vector<seal::Plaintext> database_pt;
    for (const auto& msg : database_) {
        seal::Plaintext pt;
        // crypto_provider_->encoder() 返回一个 seal::BatchEncoder
        crypto_provider_->encoder()->encode(msg.to_vector(), pt);
        database_pt.push_back(pt);
    }

    // 2. 准备一个加密的零向量用于累加结果
    //    请求中的密文 req.encrypted_query 是 (c0, c1)
    //    一个全零的密文 c_zero 也是 (c0', c1')，但它加密的是0
    seal::Ciphertext result_ct;
    // 从请求密文中复制元数据，但其加密内容实际为0（或通过加密一个0向量得到）
    result_ct = crypto_provider_->create_zero_ciphertext_like(req.encrypted_query);

    // 3. 执行同态计算 (核心部分)
    //    计算 Σ (encrypted_query[i] * database_pt[i])
    //    在实践中，这等于 encrypted_query 和 database 的点积
    //    如果使用了 Batching，一个 HE 乘法就可以处理数千个消息的点积
    seal::Ciphertext temp_ct;
    for (size_t i = 0; i < database_pt.size(); ++i) {
        // evaluator.multiply_plain 执行密文-明文乘法
        // temp_ct = req.encrypted_query * database_pt[i]
        evaluator.multiply_plain(req.encrypted_query, database_pt[i], temp_ct);

        // evaluator.add_inplace 将结果累加到 result_ct
        // result_ct = result_ct + temp_ct
        evaluator.add_inplace(result_ct, temp_ct);
    }

    RetrievalResponse resp;
    resp.encrypted_message = result_ct;
    return resp;
}
```
**客户端 `OMRClient::decrypt_response()`**
```cpp
// src/client.cpp
Message OMRClient::decrypt_response(const RetrievalResponse& resp) {
    // 使用私钥解密
    Plaintext result_pt = crypto_provider_->decrypt(resp.encrypted_message, he_sk_);

    // 解码出最终消息
    return crypto_provider_->decode_message(result_pt);
}
```

---

## 4. 实验与性能分析

科学的性能评测是衡量 OMR 方案优劣的关键。

### 4.1 如何运行实验

`benchmark/benchmark.cpp` 程序是评测的入口。它应该支持通过命令行参数进行配置，以测试不同场景下的性能。

**示例命令**：
```bash
# 测试 100 万条消息，使用 16 个线程处理
./build/bin/benchmark --messages 1000000 --threads 16

# 测试不同的 HE 参数方案
./build/bin/benchmark --messages 500000 --he_params "fast_but_less_secure"
```

### 4.2 关键性能指标及 C++ 测量方法

1.  **通信开销 (Communication Overhead)**
    *   **定义**：客户端与服务器之间传输数据的大小（字节）。主要包括检索请求（`RetrievalRequest`）和检索响应（`RetrievalResponse`）的大小。
    *   **C++ 测量方法 (综合示例)**:
        下面是一个更完整的性能测试函数示例，它同时测量了计算时间和通信开销。
        ```cpp
        #include <iostream>
        #include <vector>
        #include <chrono>
        #include <sstream>
        #include "seal/seal.h"
        #include "server.h" // 假设 OMRServer 在此定义

        // 运行一次完整的服务器端基准测试
        void run_server_benchmark(OMRServer& server, const RetrievalRequest& request) {
            // 1. 测量计算时间
            auto start_time = std::chrono::high_resolution_clock::now();

            RetrievalResponse response = server.handle_retrieval_request(request);

            auto end_time = std::chrono::high_resolution_clock::now();
            auto duration_us = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time).count();

            // 2. 测量响应的通信开销
            std::stringstream ss;
            long long communication_bytes = 0;
            if (response.encrypted_message.size() > 0) {
                communication_bytes = response.encrypted_message.save(ss);
            }

            // 3. 打印结果
            std::cout << "Server computation time: "
                      << duration_us << " microseconds ("
                      << static_cast<double>(duration_us) / 1000.0 << " ms)" << std::endl;

            std::cout << "Response communication size: "
                      << communication_bytes << " bytes ("
                      << static_cast<double>(communication_bytes) / 1024.0 << " KB)" << std::endl;
        }
        ```

2.  **服务器端计算时间 (Server-side Computation Time)**
    *   **定义**：服务器处理一个请求所需的总时间，特别是 `handle_retrieval_request` 函数的执行时间。
    *   **C++ 测量方法**: 见上方的综合示例。


3.  **客户端计算时间 (Client-side Computation Time)**
    *   **定义**：客户端生成请求和解密响应所需的时间。
    *   **C++ 测量方法**: 同样使用 `<chrono>` 库，分别对 `generate_retrieval_request` 和 `decrypt_response` 两个函数计时。

### 4.3 如何解读数据

收集到原始数据后，需要进行分析和可视化。

*   **绘制性能曲线**：使用 `benchmark/plotting/` 中的 Python 或 Gnuplot 脚本，将数据绘制成图表。
    *   **横轴**: 数据库中的消息总数 (e.g., from 10k to 10M)。
    *   **纵轴**: 服务器计算时间 (ms) 或 通信开销 (KB/MB)。
*   **分析权衡 (Trade-offs)**：
    *   **安全 vs. 性能**: HE 的安全参数（如多项式度 `poly_modulus_degree`）越高，安全性越强，但密文尺寸和计算时间都会显著增加。实验时应测试几组不同的参数，以找到满足应用需求的最佳平衡点。
    *   **计算 vs. 通信**: 某些 OMR 变体可能计算更快，但需要更多轮的通信。需要综合评估总延迟。

### 4.4 关键配置参数详解

选择正确的同态加密（HE）参数是整个方案的重中之重，它直接决定了应用的安全性、性能和功能。以下是使用 SEAL 等库时需要配置的核心参数及其影响：

| 参数 (`seal::EncryptionParameters`) | 解释 | 对性能的影响 | 对安全性的影响 |
| :--- | :--- | :--- | :--- |
| `poly_modulus_degree` | **多项式模数阶数 (N)**。必须是2的幂。它定义了密文和明文“槽”（slots）的数量（通常为N/2）。 | **巨大影响**。N 越大，计算越慢，密文尺寸越大。 | **巨大影响**。N 是安全级别的主要贡献者。128位安全通常要求 N ≥ 8192。 |
| `coeff_modulus` | **系数模数 (q)**。由一系列素数组成。它的总比特长度决定了密文在计算过程中能够承受多少“噪声”增长。 | **显著影响**。q 越大，计算越慢。乘法操作会消耗 q 的“预算”。 | **显著影响**。q 的大小与 N 一起决定了安全级别。 |
| `plain_modulus` | **明文模数 (t)**。决定了明文数据（编码前）的取值范围。 | **较小影响**。t 越大，噪声增长越快，可能会迫使你使用更大的 `coeff_modulus`。 | **间接影响**。t 的选择会影响噪声预算，从而间接影响方案的可靠性。 |

**配置策略小结**:
*   **第一步**: 根据你的应用需要支持的计算复杂度（主要是乘法深度）来选择合适的 `coeff_modulus`。
*   **第二步**: 根据你需要的安全级别（如128位、192位）和已选的 `coeff_modulus`，从 [homomorphicencryption.org 安全标准](https://homomorphicencryption.org/introduction/) 中选择一个最小的、满足要求的 `poly_modulus_degree`。
*   **第三步**: `plain_modulus` 的选择应足够大以容纳你的数据，但又不能太大以免噪声增长过快。对于需要进行大量加法和几次乘法的应用，选择一个中等大小的素数（如65537）是常见的做法。

## 5. 结论

通过本文档的分析，我们深入了解了 OMR 库在 C++ 中的具体实现。核心在于利用 `CryptoProvider` 类封装底层密码学库，并通过 `OMRClient` 和 `OMRServer` 实现协议的交互逻辑。科学的性能评测需要关注通信、计算两大维度，并结合业务需求，在安全性和效率之间做出合理的权衡。
