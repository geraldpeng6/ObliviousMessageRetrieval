# Implementation Flow and Code Structure

This document provides detailed Mermaid diagrams explaining the implementation flow and code structure of the OMR system.

## 1. Main Function Flow

```mermaid
flowchart TD
    subgraph "Program Entry 程序入口"
        direction TB
        M1[main() Function<br/>主函数] --> M2[User Menu<br/>用户菜单]
        M2 --> M3{Select Option<br/>选择选项}
        M3 -->|OMD1p| M4[OMD Single Thread<br/>OMD单线程]
        M3 -->|OMR2p| M5[OMR2 Single Thread<br/>OMR2单线程]
        M3 -->|OMR3p| M6[OMR3 Single Thread<br/>OMR3单线程]
        M3 -->|Multi-core| M7[Multi-core Execution<br/>多核执行]
    end
    
    subgraph "Setup Phase 设置阶段"
        direction TB
        S1[Initialize Parameters<br/>初始化参数] --> S2[Generate PVW Keys<br/>生成PVW密钥]
        S2 --> S3[Generate BFV Keys<br/>生成BFV密钥]
        S3 --> S4[Create Switching Keys<br/>创建切换密钥]
        S4 --> S5[Setup Complete<br/>设置完成]
    end
    
    subgraph "Execution Flow 执行流程"
        direction TB
        E1[Prepare Transactions<br/>准备交易] --> E2[Server Phase 1<br/>服务器阶段1]
        E2 --> E3[Server Phase 2<br/>服务器阶段2]
        E3 --> E4[Client Decoding<br/>客户端解码]
        E4 --> E5[Verify Results<br/>验证结果]
    end
    
    M4 --> S1
    M5 --> S1
    M6 --> S1
    M7 --> S1
    S5 --> E1
    
    style M1 fill:#e3f2fd
    style S5 fill:#fff3e0
    style E5 fill:#e8f5e8
```

## 2. Class and Function Hierarchy

```mermaid
classDiagram
    class MainController {
        +main()
        +OMR2()
        +OMR3()
        +multiCoreExecution()
    }
    
    class TransactionManager {
        +preparinngTransactionsFormal()
        +createDatabase()
        +loadDataSingle()
        +saveClues()
        +loadClues()
    }
    
    class ServerOperations {
        +serverOperations1obtainPackedSIC()
        +serverOperations2therest()
        +serverOperations3therest()
    }
    
    class ClientOperations {
        +receiverDecoding()
        +receiverDecodingOMR3()
        +decodeIndices()
        +decodeIndicesRandom()
        +formRhs()
        +formLhsWeights()
        +equationSolving()
    }
    
    class CryptographicUtils {
        +generateSwitchingKey()
        +computeBplusASPVWOptimized()
        +newRangeCheckPVW()
        +expandSIC()
        +EvalMultMany_inpace()
        +innerSum_inplace()
    }
    
    class RetrievalOperations {
        +deterministicIndexRetrieval()
        +randomizedIndexRetrieval()
        +payloadRetrievalOptimizedwithWeights()
        +payloadPackingOptimized()
    }
    
    MainController --> TransactionManager
    MainController --> ServerOperations
    MainController --> ClientOperations
    ServerOperations --> CryptographicUtils
    ServerOperations --> RetrievalOperations
    ClientOperations --> CryptographicUtils
```

## 3. Data Flow Between Components

```mermaid
graph TD
    subgraph "Input Data 输入数据"
        direction TB
        I1[Transaction Database<br/>交易数据库] --> I2[Payloads<br/>载荷]
        I1 --> I3[Clues<br/>线索]
        I4[User Parameters<br/>用户参数] --> I5[Number of Messages<br/>消息数量]
        I4 --> I6[Pertinent Count<br/>相关数量]
    end
    
    subgraph "Processing Pipeline 处理管道"
        direction TB
        P1[Load Data<br/>加载数据] --> P2[Encrypt Clues<br/>加密线索]
        P2 --> P3[Generate Keys<br/>生成密钥]
        P3 --> P4[Server Processing<br/>服务器处理]
        P4 --> P5[Client Decoding<br/>客户端解码]
        P5 --> P6[Result Verification<br/>结果验证]
    end
    
    subgraph "Output Results 输出结果"
        direction TB
        O1[Recovered Messages<br/>恢复的消息] --> O2[Performance Metrics<br/>性能指标]
        O2 --> O3[Timing Data<br/>时间数据]
        O3 --> O4[Memory Usage<br/>内存使用]
        O4 --> O5[Success Rate<br/>成功率]
    end
    
    I2 --> P1
    I3 --> P2
    I5 --> P3
    I6 --> P4
    P6 --> O1
    
    style I1 fill:#fff3e0
    style P4 fill:#e1f5fe
    style O1 fill:#e8f5e8
```

## 4. Memory and Performance Management

```mermaid
flowchart TD
    subgraph "Memory Management 内存管理"
        direction TB
        MM1[Memory Pool Allocation<br/>内存池分配] --> MM2[Batch Processing<br/>批处理]
        MM2 --> MM3[Garbage Collection<br/>垃圾回收]
        MM3 --> MM4[Memory Optimization<br/>内存优化]
    end

    subgraph "Parallel Processing 并行处理"
        direction TB
        PP1[Thread Pool Creation<br/>线程池创建] --> PP2[Task Distribution<br/>任务分配]
        PP2 --> PP3[Core Assignment<br/>核心分配]
        PP3 --> PP4[Synchronization<br/>同步]
        PP4 --> PP5[Result Aggregation<br/>结果聚合]
    end

    subgraph "Performance Monitoring 性能监控"
        direction TB
        PM1[Timer Start<br/>计时器启动] --> PM2[Operation Tracking<br/>操作跟踪]
        PM2 --> PM3[Resource Monitoring<br/>资源监控]
        PM3 --> PM4[Bottleneck Detection<br/>瓶颈检测]
        PM4 --> PM5[Performance Report<br/>性能报告]
    end

    MM4 --> PP1
    PP5 --> PM1

    style MM4 fill:#fff3e0
    style PP5 fill:#e1f5fe
    style PM5 fill:#e8f5e8
```

## 5. Error Handling and Debugging

```mermaid
graph TD
    subgraph "Error Detection 错误检测"
        direction TB
        ED1[Input Validation<br/>输入验证] --> ED2[Type Checking<br/>类型检查]
        ED2 --> ED3[Range Validation<br/>范围验证]
        ED3 --> ED4[Consistency Check<br/>一致性检查]
    end

    subgraph "Exception Handling 异常处理"
        direction TB
        EH1[Try-Catch Blocks<br/>Try-Catch块] --> EH2[Error Logging<br/>错误日志]
        EH2 --> EH3[Graceful Degradation<br/>优雅降级]
        EH3 --> EH4[Recovery Mechanism<br/>恢复机制]
    end

    subgraph "Debugging Support 调试支持"
        direction TB
        DS1[Debug Flags<br/>调试标志] --> DS2[Verbose Output<br/>详细输出]
        DS2 --> DS3[State Inspection<br/>状态检查]
        DS3 --> DS4[Trace Generation<br/>跟踪生成]
    end

    ED4 --> EH1
    EH4 --> DS1

    style ED4 fill:#fff3e0
    style EH4 fill:#e1f5fe
    style DS4 fill:#e8f5e8
```

## 6. Configuration and Customization

```mermaid
flowchart LR
    subgraph "Global Configuration 全局配置"
        direction TB
        GC1[global.h<br/>全局头文件] --> GC2[Parameter Settings<br/>参数设置]
        GC2 --> GC3[numcores<br/>核心数]
        GC2 --> GC4[poly_modulus_degree<br/>多项式模数度]
        GC2 --> GC5[numOfTransactions<br/>交易数量]
    end

    subgraph "Runtime Configuration 运行时配置"
        direction TB
        RC1[Command Line Args<br/>命令行参数] --> RC2[User Input<br/>用户输入]
        RC2 --> RC3[Dynamic Settings<br/>动态设置]
        RC3 --> RC4[Execution Mode<br/>执行模式]
    end

    subgraph "Customization Options 自定义选项"
        direction TB
        CO1[Algorithm Selection<br/>算法选择] --> CO2[OMD vs OMR<br/>OMD对比OMR]
        CO2 --> CO3[Thread Count<br/>线程数]
        CO3 --> CO4[Memory Limits<br/>内存限制]
    end

    GC5 --> RC1
    RC4 --> CO1

    style GC1 fill:#fff3e0
    style RC4 fill:#e1f5fe
    style CO4 fill:#e8f5e8
```
