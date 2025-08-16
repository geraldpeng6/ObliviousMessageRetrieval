#pragma once

// 包含必要的头文件 - Include necessary header files
#include<iostream>
#include<fstream>
#include<string>
#include<experimental/filesystem>
using namespace std;

/**
 * 创建数据库 - Create database
 * @param num_of_transactions 交易数量 - Number of transactions
 * @param payloadSize 载荷大小 - Payload size
 */
void createDatabase(int num_of_transactions = 524288, int payloadSize = 306){
    // 为每个交易创建文件 - Create file for each transaction
    for(int i = 0; i < num_of_transactions; i++){
        ofstream datafile;                              // 输出文件流 - Output file stream
        auto tempi = i % 65537;                         // 临时变量 - Temporary variable
        datafile.open ("../data/payloads/"+to_string(i)+".txt"); // 打开文件 - Open file
        // 写入载荷数据 - Write payload data
        for(int j = 0; j < payloadSize; j++){
            datafile << (65537 - tempi+j)%65537 << "\n";
        }
        datafile.close();                               // 关闭文件 - Close file
    }
}

/**
 * 加载单个数据 - Load single data
 * @param i 索引 - Index
 * @param payloadSize 载荷大小 - Payload size
 * @return 返回载荷数据向量 - Returns payload data vector
 */
vector<uint64_t> loadDataSingle(int i, int payloadSize = 306){
    vector<uint64_t> ret;                               // 返回向量 - Return vector

    ret.resize(payloadSize);                            // 调整大小 - Resize
    ifstream datafile;                                  // 输入文件流 - Input file stream
    datafile.open ("../data/payloads/"+to_string(i)+".txt"); // 打开文件 - Open file
    // 读取载荷数据 - Read payload data
    for(int j = 0; j < payloadSize; j++){
        datafile >> ret[j];
    }
    datafile.close();                                   // 关闭文件 - Close file

    return ret;                                         // 返回结果 - Return result
}

/**
 * 保存线索 - Save clues
 * @param clue PVW密文线索 - PVW ciphertext clue
 * @param transaction_num 交易编号 - Transaction number
 */
void saveClues(const PVWCiphertext& clue, int transaction_num){
    ofstream datafile;                                  // 输出文件流 - Output file stream
    datafile.open ("../data/clues/"+to_string(transaction_num)+".txt"); // 打开文件 - Open file

    // 保存a部分 - Save a part
    for(size_t i = 0; i < clue.a.GetLength(); i++){
        datafile << clue.a[i].ConvertToInt() << "\n";
    }
    // 保存b部分 - Save b part
    for(size_t i = 0; i < clue.b.GetLength(); i++){
        datafile << clue.b[i].ConvertToInt() << "\n";
    }

    datafile.close();                                   // 关闭文件 - Close file
}

/**
 * 加载数据 - Load data
 * @param msgs 消息向量 - Messages vector
 * @param start 起始索引 - Start index
 * @param end 结束索引 - End index
 * @param payloadSize 载荷大小 - Payload size
 */
void loadData(vector<vector<uint64_t>>& msgs, const int& start, const int& end, int payloadSize = 306){
    msgs.resize(end-start);                             // 调整消息向量大小 - Resize messages vector
    // 加载指定范围的数据 - Load data in specified range
    for(int i = start; i < end; i++){
        msgs[i-start].resize(payloadSize);              // 调整单个消息大小 - Resize individual message
        ifstream datafile;                              // 输入文件流 - Input file stream
        datafile.open("../data/payloads/"+to_string(i)+".txt"); // 打开文件 - Open file
        // 读取载荷数据 - Read payload data
        for(int j = 0; j < payloadSize; j++){
            datafile >> msgs[i-start][j];
        }
        datafile.close();                               // 关闭文件 - Close file
    }
}

/**
 * 加载线索 - Load clues
 * @param clues 线索向量 - Clues vector
 * @param start 起始索引 - Start index
 * @param end 结束索引 - End index
 * @param param PVW参数 - PVW parameters
 */
void loadClues(vector<PVWCiphertext>& clues, const int& start, const int& end, const PVWParam& param){
    clues.resize(end-start);                            // 调整线索向量大小 - Resize clues vector
    // 加载指定范围的线索 - Load clues in specified range
    for(int i = start; i < end; i++){
        clues[i-start].a = NativeVector(param.n);       // 初始化a向量 - Initialize a vector
        clues[i-start].b = NativeVector(param.ell);     // 初始化b向量 - Initialize b vector

        ifstream datafile;                              // 输入文件流 - Input file stream
        datafile.open ("../data/clues/"+to_string(i)+".txt"); // 打开文件 - Open file

        // 读取a部分 - Read a part
        for(int j = 0; j < param.n; j++){
            uint64_t temp;                              // 临时变量 - Temporary variable
            datafile >> temp;
            clues[i-start].a[j] = temp;
        }

        // 读取b部分 - Read b part
        for(int j = 0; j < param.ell; j++){
            uint64_t temp;                              // 临时变量 - Temporary variable
            datafile >> temp;
            clues[i-start].b[j] = temp;
        }
    }
}