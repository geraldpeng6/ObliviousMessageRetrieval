# Oblivious Message Retrieval (OMR) System Overview

This document provides comprehensive Mermaid diagrams explaining the ObliviousMessageRetrieval project architecture, data flow, and cryptographic protocols.

## 1. High-Level System Architecture

```mermaid
graph TB
    subgraph "Client/Recipient 客户端/接收者"
        direction TB
        CK[Key Generation<br/>密钥生成]
        CQ[Query Preparation<br/>查询准备]
        CD[Decoding & Recovery<br/>解码与恢复]
        CK --> CQ
        CQ --> CD
    end
    
    subgraph "Server/Detector 服务器/探测器"
        direction TB
        SP1[Phase 1: Detection<br/>阶段1：检测]
        SP2[Phase 2: Retrieval<br/>阶段2：检索]
        SP1 --> SP2
    end
    
    subgraph "Data Storage 数据存储"
        direction TB
        BB[Bulletin Board<br/>公告板]
        PL[Payloads<br/>载荷数据]
        CL[Clues<br/>线索数据]
        BB --> PL
        BB --> CL
    end
    
    CK -.->|Detection Key<br/>检测密钥| SP1
    CQ -.->|Switching Key<br/>切换密钥| SP1
    CL -.->|Encrypted Clues<br/>加密线索| SP1
    SP1 -.->|Packed SIC<br/>打包SIC| SP2
    PL -.->|Message Payloads<br/>消息载荷| SP2
    SP2 -.->|Encrypted Results<br/>加密结果| CD
    
    style Client fill:#e1f5fe
    style Server fill:#f3e5f5
    style "Data Storage" fill:#e8f5e8
```

## 2. Cryptographic Protocol Flow

```mermaid
sequenceDiagram
    participant C as Client 客户端
    participant S as Server 服务器
    participant DB as Database 数据库
    
    Note over C,DB: Setup Phase 设置阶段
    C->>C: Generate PVW & BFV Keys<br/>生成PVW和BFV密钥
    C->>C: Create Detection Key<br/>创建检测密钥
    C->>C: Create Switching Key<br/>创建切换密钥
    
    Note over C,DB: Phase 1: Message Detection 阶段1：消息检测
    C->>S: Send Detection Key<br/>发送检测密钥
    DB->>S: Load Clues (PVW Ciphertexts)<br/>加载线索(PVW密文)
    S->>S: Homomorphic Decryption<br/>同态解密
    S->>S: Range Check & Packing<br/>范围检查与打包
    S->>C: Return Packed SIC<br/>返回打包的SIC
    
    Note over C,DB: Phase 2: Message Retrieval 阶段2：消息检索
    DB->>S: Load Payloads<br/>加载载荷
    S->>S: Expand SIC<br/>扩展SIC
    S->>S: Index Retrieval<br/>索引检索
    S->>S: Payload Multiplication<br/>载荷乘法
    S->>S: Result Packing<br/>结果打包
    S->>C: Return Encrypted Results<br/>返回加密结果
    
    Note over C,DB: Decoding Phase 解码阶段
    C->>C: Decrypt Results<br/>解密结果
    C->>C: Solve Linear Equations<br/>求解线性方程
    C->>C: Recover Original Messages<br/>恢复原始消息
```

## 3. Data Structure and Encoding

```mermaid
graph LR
    subgraph "Message Structure 消息结构"
        direction TB
        M[Message 消息]
        M --> P[Payload 载荷]
        M --> C[Clue 线索]
        P --> PD[Payload Data<br/>载荷数据<br/>306 elements]
        C --> CA[Clue.a<br/>PVW密文a部分]
        C --> CB[Clue.b<br/>PVW密文b部分]
    end
    
    subgraph "Encoding Process 编码过程"
        direction TB
        PT[Plaintext Message<br/>明文消息]
        PT --> PVW[PVW Encryption<br/>PVW加密]
        PVW --> CT[Ciphertext Clue<br/>密文线索]
        
        PT --> BFV[BFV Encoding<br/>BFV编码]
        BFV --> PP[Packed Payload<br/>打包载荷]
    end
    
    subgraph "Storage Format 存储格式"
        direction TB
        FS[File System<br/>文件系统]
        FS --> PF[Payload Files<br/>载荷文件<br/>../data/payloads/]
        FS --> CF[Clue Files<br/>线索文件<br/>../data/clues/]
    end
    
    M -.-> PT
    CT -.-> CF
    PP -.-> PF
    
    style "Message Structure" fill:#fff2cc
    style "Encoding Process" fill:#d5e8d4
    style "Storage Format" fill:#f8cecc
```

## 4. Server Operations Detailed Flow

```mermaid
flowchart TD
    subgraph "Phase 1: Detection 阶段1：检测"
        direction TB
        A1[Load PVW Clues<br/>加载PVW线索] --> A2[Apply Switching Key<br/>应用切换密钥]
        A2 --> A3[Compute B+AS<br/>计算B+AS]
        A3 --> A4[Range Check<br/>范围检查]
        A4 --> A5[Pack Results<br/>打包结果]
        A5 --> A6[Packed SIC<br/>打包的SIC]
    end

    subgraph "Phase 2: Retrieval 阶段2：检索"
        direction TB
        B1[Expand SIC<br/>扩展SIC] --> B2[Transform to NTT<br/>转换为NTT形式]
        B2 --> B3{Retrieval Type<br/>检索类型}
        B3 -->|Deterministic<br/>确定性| B4[Deterministic Index Retrieval<br/>确定性索引检索]
        B3 -->|Randomized<br/>随机化| B5[Randomized Index Retrieval<br/>随机化索引检索]
        B4 --> B6[Payload Multiplication<br/>载荷乘法]
        B5 --> B6
        B6 --> B7[Weight Application<br/>权重应用]
        B7 --> B8[Result Packing<br/>结果打包]
        B8 --> B9[Final Results<br/>最终结果]
    end

    A6 --> B1

    style A6 fill:#e3f2fd
    style B9 fill:#e8f5e8
```

## 5. Client Decoding Process

```mermaid
flowchart TD
    subgraph "Input Processing 输入处理"
        direction TB
        I1[Encrypted LHS<br/>加密的左侧] --> D1[Decrypt LHS<br/>解密左侧]
        I2[Encrypted RHS<br/>加密的右侧] --> D2[Decrypt RHS<br/>解密右侧]
    end

    subgraph "Index Recovery 索引恢复"
        direction TB
        D1 --> IR1[Decode Indices<br/>解码索引]
        IR1 --> IR2{Decoding Type<br/>解码类型}
        IR2 -->|Deterministic<br/>确定性| IR3[Bit Extraction<br/>位提取]
        IR2 -->|Randomized<br/>随机化| IR4[Collision Resolution<br/>冲突解决]
        IR3 --> IR5[Pertinent Indices<br/>相关索引]
        IR4 --> IR5
    end

    subgraph "Equation Solving 方程求解"
        direction TB
        D2 --> ES1[Form RHS Matrix<br/>构建右侧矩阵]
        IR5 --> ES2[Form LHS Matrix<br/>构建左侧矩阵]
        ES1 --> ES3[Gaussian Elimination<br/>高斯消元]
        ES2 --> ES3
        ES3 --> ES4[Back Substitution<br/>回代求解]
        ES4 --> ES5[Recovered Messages<br/>恢复的消息]
    end

    style IR5 fill:#fff3e0
    style ES5 fill:#e8f5e8
```
