# OMR Project Documentation

This directory contains comprehensive Mermaid diagrams explaining the ObliviousMessageRetrieval (OMR) project architecture, implementation, and performance characteristics.

## 📋 Documentation Overview

### 1. [System Overview](system-overview.md)
- **High-Level System Architecture**: Complete system overview showing client, server, and data storage components
- **Cryptographic Protocol Flow**: Detailed sequence diagram of the OMR protocol phases
- **Data Structure and Encoding**: Message structure, encoding processes, and storage formats
- **Server Operations Flow**: Detailed flow of detection and retrieval phases
- **Client Decoding Process**: Input processing, index recovery, and equation solving

### 2. [Cryptographic Details](cryptographic-details.md)
- **PVW to BFV Conversion**: Homomorphic encryption scheme conversion process
- **Homomorphic Operations**: Multiplication trees, rotation operations, and packing
- **Index Retrieval Mechanisms**: Deterministic vs randomized retrieval methods
- **Mathematical Operations**: Modular arithmetic, Gaussian elimination, polynomial operations
- **Error Handling and Optimization**: Security measures and performance optimizations

### 3. [Implementation Flow](implementation-flow.md)
- **Main Function Flow**: Program entry points and execution paths
- **Class and Function Hierarchy**: Code organization and component relationships
- **Data Flow Between Components**: Input processing, pipeline stages, and output generation
- **Memory and Performance Management**: Resource allocation and optimization strategies
- **Error Handling and Debugging**: Exception handling and debugging support
- **Configuration and Customization**: Parameter settings and runtime options

### 4. [Performance Analysis](performance-analysis.md)
- **Performance Bottlenecks**: Computational, memory, and I/O bottlenecks identification
- **Optimization Strategies**: Algorithmic, parallel processing, and memory optimizations
- **Performance Metrics**: Timing, memory, and throughput measurements
- **Scalability Analysis**: Horizontal, vertical, and algorithmic scaling approaches
- **Benchmarking Framework**: Testing configurations and measurement tools
- **Real-world Considerations**: Network latency, security overhead, and deployment factors

## 🎯 Key Features Explained

### Oblivious Message Retrieval (OMR)
The OMR system enables privacy-preserving message retrieval where:
- **Clients** can retrieve their messages without revealing which messages they're interested in
- **Servers** can process queries without learning the query content or results
- **Privacy** is maintained through advanced cryptographic techniques

### Two-Phase Protocol
1. **Detection Phase (阶段1：检测)**: Quickly determine if relevant messages exist
2. **Retrieval Phase (阶段2：检索)**: Securely retrieve the actual message content

### Cryptographic Foundations
- **PVW Encryption**: For initial message encryption and clue generation
- **BFV Homomorphic Encryption**: For server-side computations
- **Switching Keys**: For converting between encryption schemes
- **Gaussian Elimination**: For client-side message recovery

## 🔧 Technical Highlights

### Performance Optimizations
- **Batch Processing**: Efficient handling of multiple messages
- **Parallel Execution**: Multi-core processing support
- **Memory Management**: Optimized memory allocation and reuse
- **Tree-based Multiplication**: Depth-optimal homomorphic operations

### Security Features
- **Semantic Security**: Cryptographically secure against chosen-plaintext attacks
- **Oblivious Computation**: Server learns nothing about client queries
- **Noise Management**: Proper handling of cryptographic noise
- **Side-channel Protection**: Resistance to timing and power analysis

## 📊 Diagram Types Used

### Flowcharts
- System architecture overviews
- Process flows and decision trees
- Error handling and optimization paths

### Sequence Diagrams
- Protocol interactions between components
- Temporal flow of operations
- Communication patterns

### Class Diagrams
- Code structure and relationships
- Component hierarchies
- Interface definitions

### Graph Diagrams
- Data flow and dependencies
- Network topologies
- Mathematical relationships

## 🚀 Getting Started

1. **Read the System Overview** to understand the high-level architecture
2. **Study the Cryptographic Details** to grasp the security mechanisms
3. **Explore the Implementation Flow** to understand the code structure
4. **Review the Performance Analysis** for optimization insights

## 🔍 Navigation Tips

- Each diagram includes both **English** and **Chinese (中文)** labels for international accessibility
- Color coding is used consistently across diagrams:
  - 🔵 **Blue**: Input/Setup phases
  - 🟡 **Yellow**: Processing/Computation phases  
  - 🟢 **Green**: Output/Results phases
  - 🔴 **Red**: Error/Warning conditions
- Diagrams are designed to be viewed in sequence for progressive understanding
- Cross-references between documents help navigate related concepts

## 📝 Contributing

When adding new diagrams or updating existing ones:
1. Follow the established color scheme and naming conventions
2. Include both English and Chinese labels where appropriate
3. Maintain consistent styling across all diagrams
4. Update this README when adding new documentation files

## 🔗 Related Resources

- [Main Project Repository](../README.md)
- [Code Architecture Analysis](../Code_Architecture_Analysis_CN.md)
- [Library Introduction](../OMR_Library_Intro_CN.md)
- [System Architecture](../System_Architecture_Mermaid.md)
