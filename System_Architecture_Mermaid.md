# 系统架构 Mermaid 图

这是一个根据项目架构图和代码分析得出的系统流程图。

```mermaid
graph LR
    subgraph Sender
        direction LR
        Payload -- "与" --> Message_Plaintext(明文消息)
        Clue -- "与" --> Message_Plaintext
        Message_Plaintext -- "PVW.Enc 加密" --> Message_Ciphertext(密文消息)
    end

    subgraph Bulletin
        direction TB
        Payloads[Payloads 1..N]
        Clues[Clues 1..N]
    end

    subgraph Detector
        direction TB
        Clues_in["1. Clues (PVW 密文)"] --> HD{"2. 同态解密"}
        detection_key["来自接收者的 detection key"] --> HD
        HD --> PV["3. 关联向量 (PV)<br/>(BFV 密文)"]
        PV -- "与 Payloads 逐元素相乘" --> Multiply("4. 乘法")
        Payloads_in[Payloads] --> Multiply
        Multiply --> Accumulate("5. 累加")
        Accumulate --> Digest_out["6. Digest (BFV 密文)"]
    end

    subgraph Recipient
        direction TB
        subgraph SecretKeys [密钥]
            PVW_sk[PVW.sk]
            BFV_sk[BFV.sk]
        end
        SecretKeys -- "生成" --> PublicKeys[公钥/转换密钥]
        
        Digest_in[Digest] -- "解密与高斯消元" --> Plaintext_Payloads(明文 Payloads)
        SecretKeys -- "用于解密" --> Digest_in
    end

    Sender -- "发布消息" --> Bulletin
    Bulletin -- "提供 Clues" --> Clues_in
    Bulletin -- "提供 Payloads" --> Payloads_in
    PublicKeys -- "生成并发送" --> detection_key
    Detector -- "发送 Digest" --> Digest_in

    style Sender fill:#f9f,stroke:#333,stroke-width:2px
    style Bulletin fill:#eee,stroke:#333,stroke-width:2px
    style Detector fill:#ccf,stroke:#333,stroke-width:2px
    style Recipient fill:#cfc,stroke:#333,stroke-width:2px
```

## 流程解读

1.  **Sender (发送者)**: 将 `Payload`（载荷）和 `Clue`（线索）打包成一条明文消息，并使用 `PVW` 公钥进行加密，形成密文消息。
2.  **Bulletin (公告板)**: 这是一个概念上的组件，存储了所有由发送者发布的 `Payloads` 和加密后的 `Clues`。
3.  **Detector (探测器)**:
    *   从 `Bulletin` 获取所有的 `Clues` 和 `Payloads`。
    *   使用从 `Recipient` 处获得的 `detection key`（检测密钥），对 `Clues` 进行同态解密，得到一个加密状态下的“关联向量” (`Pertinency Vector`)。这个向量指明了哪些消息是目标消息。
    *   将这个加密的关联向量与 `Payloads` 进行同态乘法，然后将结果累加起来，生成一个最终的 `Digest`（摘要）密文。
4.  **Recipient (接收者)**:
    *   首先，`Recipient` 生成系统所需的所有密钥（公钥和私钥）。它将用于 `Detector` 的 `detection key` 发送给 `Detector`。
    *   接收到 `Detector` 计算出的 `Digest` 后，使用自己的私钥对其进行解密，并通过高斯消元等数学方法，最终恢复出自己感兴趣的明文 `Payloads`。

这个流程实现了“不经意消息检索”（OMR）的核心思想：`Detector` 在不知道哪些消息被检索、也不知道消息内容的情况下，帮助 `Recipient`完成了数据筛选和提取。
