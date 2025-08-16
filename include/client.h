#pragma once

// 包含必要的头文件 - Include necessary header files
#include "seal/seal.h"
#include <algorithm>
#include <map>

using namespace seal;
#define PROFILE

/**
 * OMD的确定性解码 - Deterministic decoding for OMD
 * @param indexPack 索引包密文 - Index pack ciphertext
 * @param num_of_transactions 交易数量 - Number of transactions
 * @param degree 多项式度数 - Polynomial degree
 * @param secret_key 私钥 - Secret key
 * @param context SEAL上下文 - SEAL context
 * @return 返回相关索引向量 - Returns pertinent indices vector
 */
vector<uint64_t> decodeIndicesOMD(const Ciphertext& indexPack, const int& num_of_transactions, const size_t& degree, const SecretKey& secret_key, const SEALContext& context){
    vector<uint64_t> pertinentIndices;                  // 相关索引 - Pertinent indices
    Decryptor decryptor(context, secret_key);           // 解密器 - Decryptor
    BatchEncoder batch_encoder(context);                // 批编码器 - Batch encoder
    vector<uint64_t> indexPackint(degree);              // 索引包整数 - Index pack integers
    Plaintext plain_result;                             // 明文结果 - Plaintext result
    decryptor.decrypt(indexPack, plain_result);         // 解密索引包 - Decrypt index pack
    batch_encoder.decode(plain_result, indexPackint);   // 解码明文 - Decode plaintext

    uint64_t counter = 0;                               // 计数器 - Counter
    // 遍历所有度数 - Iterate through all degrees
    for(size_t i = 0; i < degree; i++){
        if(indexPackint[i]){                            // 如果索引包不为零 - If index pack is non-zero
            if(indexPackint[i] & 1){                    // 检查最低位 - Check lowest bit
                pertinentIndices.push_back(counter*degree + i); // 添加相关索引 - Add pertinent index
            }
            indexPackint[i] >>= 1;                      // 右移一位 - Right shift by one
            counter += 1;                               // 增加计数器 - Increment counter
            i--;                                        // 回退一位 - Decrement i
        } else {
            counter = 0;                                // 重置计数器 - Reset counter
        }
    }

    return pertinentIndices;                            // 返回相关索引 - Return pertinent indices
}

/**
 * OMR的确定性解码 - Deterministic decoding for OMR
 * OMD的确定性编码更高效，但对整体性能影响有限 - The deterministic encoding for OMD is more efficient, but has limited affect on the overall performance
 * @param pertinentIndices 相关索引映射 - Pertinent indices map
 * @param indexPack 索引包密文 - Index pack ciphertext
 * @param num_of_transactions 交易数量 - Number of transactions
 * @param degree 多项式度数 - Polynomial degree
 * @param secret_key 私钥 - Secret key
 * @param context SEAL上下文 - SEAL context
 */
void decodeIndices(map<int, int>& pertinentIndices, const Ciphertext& indexPack, const int& num_of_transactions, const size_t& degree, const SecretKey& secret_key, const SEALContext& context){
    Decryptor decryptor(context, secret_key);           // 解密器 - Decryptor
    BatchEncoder batch_encoder(context);                // 批编码器 - Batch encoder
    vector<uint64_t> indexPackint(degree);              // 索引包整数 - Index pack integers
    Plaintext plain_result;                             // 明文结果 - Plaintext result
    decryptor.decrypt(indexPack, plain_result);         // 解密索引包 - Decrypt index pack
    batch_encoder.decode(plain_result, indexPackint);   // 解码明文 - Decode plaintext
    int counter = 0;                                    // 计数器 - Counter
    int backcounter = 16;                               // 回退计数器 - Back counter
    int idx = 0;                                        // 索引 - Index
    // 遍历所有交易 - Iterate through all transactions
    for(int i = 0; i < num_of_transactions;){
        if(!indexPackint[idx])                          // 如果索引包为零 - If index pack is zero
        {
            idx += 1;                                   // 增加索引 - Increment index
            i += backcounter;                           // 跳过回退计数器个位置 - Skip back counter positions
            backcounter = 16;                           // 重置回退计数器 - Reset back counter
            continue;
        }
        if(indexPackint[idx]&1)                         // 检查该位是否为1 - Check if that slot is 1
        {
            pertinentIndices.insert(pair<int, int>(i, counter++)); // 插入相关索引 - Insert pertinent index
        }
        indexPackint[idx] >>= 1;                        // 右移一位 - Right shift by one
        backcounter -= 1;                               // 减少回退计数器 - Decrement back counter
        i++;                                            // 增加交易索引 - Increment transaction index
    }
}

/**
 * OMR的随机化解码 - Randomized decoding for OMR
 * @param pertinentIndices 相关索引映射 - Pertinent indices map
 * @param indexPack 索引包密文向量 - Index pack ciphertext vector
 * @param indexCounter 索引计数器 - Index counter
 * @param degree 多项式度数 - Polynomial degree
 * @param secret_key 私钥 - Secret key
 * @param context SEAL上下文 - SEAL context
 */
void decodeIndicesRandom(map<int, int>& pertinentIndices, const vector<vector<Ciphertext>>& indexPack, const vector<Ciphertext>& indexCounter,
                                     const size_t& degree, const SecretKey& secret_key, const SEALContext& context){
    Decryptor decryptor(context, secret_key);           // 解密器 - Decryptor
    BatchEncoder batch_encoder(context);                // 批编码器 - Batch encoder

    int counter = 0;                                    // 计数器 - Counter
    int realNumOfPertinentMsg = 0;                      // 实际相关消息数量 - Real number of pertinent messages
    vector<uint64_t> countertemp(degree);               // 临时计数器 - Temporary counter
    Plaintext plain_result;                             // 明文结果 - Plaintext result
    decryptor.decrypt(indexCounter[0], plain_result);   // 解密第一个索引计数器 - Decrypt first index counter
    batch_encoder.decode(plain_result, countertemp);    // 解码明文 - Decode plaintext
    // 首先累加计数器以查看有多少消息 - First sum up the counters to see how many messages are there
    for(size_t i = 0; i < degree; i++){
        realNumOfPertinentMsg += countertemp[i];
    }

    // 遍历所有索引计数器 - Iterate through all index counters
    for(size_t i = 0; i < indexCounter.size(); i++){
        vector<uint64_t> plain_counter(degree), plain_one(degree), plain_two(degree); // 明文计数器和两个明文向量 - Plain counter and two plain vectors
        decryptor.decrypt(indexCounter[i], plain_result);
        batch_encoder.decode(plain_result, plain_counter);
        decryptor.decrypt(indexPack[i][0], plain_result);
        batch_encoder.decode(plain_result, plain_one);
        decryptor.decrypt(indexPack[i][1], plain_result);
        batch_encoder.decode(plain_result, plain_two);
        // 检查每个度数位置 - Check each degree position
        for(size_t j = 0; j < degree; j++){
            if(plain_counter[j] == 1){                  // 检查无冲突的槽位 - Check the slots without collision
                uint64_t index = plain_one[j]*65537 + plain_two[j]; // 计算索引 - Calculate index
                if(pertinentIndices.find(index) == pertinentIndices.end()){ // 如果索引不存在 - If index doesn't exist
                    pertinentIndices.insert(pair<int, int>(index, counter++)); // 插入新索引 - Insert new index
                }
            }
        }
        if(counter == realNumOfPertinentMsg)            // 如果找到所有相关消息 - If all pertinent messages found
            break;
    }
    if(counter != realNumOfPertinentMsg)                // 如果计数器不匹配 - If counter doesn't match
    {
        cerr << "Overflow" << endl;                     // 输出溢出错误 - Output overflow error
        exit(1);
    }
}

/**
 * 构建方程的右侧 - Construct the RHS of the equations
 * @param rhs 右侧方程组 - Right-hand side equations
 * @param packedPayloads 打包的载荷密文 - Packed payloads ciphertext
 * @param secret_key 私钥 - Secret key
 * @param degree 多项式度数 - Polynomial degree
 * @param context SEAL上下文 - SEAL context
 * @param num_of_buckets 桶的数量 - Number of buckets
 * @param payloadSlots 载荷槽位数 - Number of payload slots
 */
void formRhs(vector<vector<int>>& rhs, const Ciphertext& packedPayloads, const SecretKey& secret_key, const size_t& degree, const SEALContext& context,
                         const int num_of_buckets = 64, const int payloadSlots = 306){ // 或306 - or 306
    Decryptor decryptor(context, secret_key);           // 解密器 - Decryptor
    BatchEncoder batch_encoder(context);                // 批编码器 - Batch encoder
    vector<uint64_t> rhsint(degree);                    // 右侧整数向量 - RHS integer vector
    Plaintext plain_result;                             // 明文结果 - Plaintext result
    decryptor.decrypt(packedPayloads, plain_result);    // 解密打包载荷 - Decrypt packed payloads
    batch_encoder.decode(plain_result, rhsint);         // 解码明文 - Decode plaintext

    rhs.resize(num_of_buckets);                         // 调整右侧大小 - Resize RHS
    // 初始化所有桶 - Initialize all buckets
    for(int i = 0; i < num_of_buckets; i++){
        rhs[i].resize(payloadSlots, 0);
    }
    // 填充右侧数据 - Fill RHS data
    for(int i = 0; i < num_of_buckets; i++){
        for(int j = 0; j < payloadSlots; j++){
            rhs[i][j] = int(rhsint[i*payloadSlots + j]);
        }
    }
}

/**
 * 构建方程的左侧 - Construct the LHS of the equations
 * @param lhs 左侧方程组 - Left-hand side equations
 * @param pertinentIndices 相关索引映射 - Pertinent indices map
 * @param bipartite_map 二分图映射 - Bipartite map
 * @param weights 权重向量 - Weights vector
 * @param start 起始位置 - Start position
 * @param num_of_buckets 桶的数量 - Number of buckets
 */
void formLhsWeights(vector<vector<int>>& lhs, map<int, int>& pertinentIndices, const vector<vector<int>>& bipartite_map, vector<vector<int>>& weights,
                            const int start = 0, const int num_of_buckets = 64){ // 最后两个参数用于更多桶 - The last two parameters are for more buckets
    auto pertinentTransactionNum = pertinentIndices.size(); // 相关交易数量 - Number of pertinent transactions
    lhs.resize(num_of_buckets);                         // 调整左侧大小 - Resize LHS
    // 初始化所有桶 - Initialize all buckets
    for(int i = 0; i < num_of_buckets; i++){
        lhs[i].resize(pertinentTransactionNum);
    }

    map<int, int>::iterator itr;                        // 迭代器 - Iterator
    // 遍历所有相关索引 - Iterate through all pertinent indices
    for(itr = pertinentIndices.begin(); itr != pertinentIndices.end(); ++itr){
        auto ptr = &bipartite_map[itr->first];          // 获取二分图指针 - Get bipartite map pointer
        // 设置权重 - Set weights
        for(size_t j = 0; j < ptr->size(); j++){
            lhs[(*ptr)[j]][itr->second] = weights[itr->first][j];
        }
    }
}


/////////////////////////// 方程求解相关函数 - For equation solving

/**
 * 向量标量乘法 - Vector scalar multiplication
 * @param output 输出向量 - Output vector
 * @param input 输入向量 - Input vector
 * @param k 标量 - Scalar
 */
inline
void mult_scalar_vec(vector<int>& output, const vector<int>& input, int k){
    output.resize(input.size());                        // 调整输出大小 - Resize output
    for(size_t i = 0; i < output.size(); i++){
        long temp = ((long)input[i]*(long)k)%65537;     // 计算乘积并取模 - Calculate product and modulo
        output[i] = temp;
        if(output[i] < 0)                               // 检查负数 - Check for negative numbers
            cerr <<temp << " " << k << " " << input[i] << endl;
    }
}

/**
 * 就地向量减法 - In-place vector subtraction
 * @param output 输出向量 - Output vector
 * @param input 输入向量 - Input vector
 * @param numToSolve 要求解的数量 - Number to solve
 */
inline
void subtract_two_vec_inplace(vector<int>& output, const vector<int>& input, int numToSolve = -1){
    if(output.size() != input.size())                   // 检查大小是否相等 - Check if sizes are equal
    {
        cerr << "substracting size not equal." << endl;
    }
    if(numToSolve == -1) numToSolve = input.size();     // 设置默认求解数量 - Set default solve count
    for(int i = 0; i < numToSolve; i++){
        output[i] -= input[i];                          // 执行减法 - Perform subtraction
        output[i] %= 65537;                             // 取模 - Modulus
        while(output[i] < 0){                           // 确保结果为正 - Ensure positive result
            output[i] += 65537;
        }
    }
}
 
/**
 * 以下两个函数来自：https://www.geeksforgeeks.org/multiplicative-inverse-under-modulo-m/
 * The following two functions are from: https://www.geeksforgeeks.org/multiplicative-inverse-under-modulo-m/
 * 计算模m下的x^y - To compute x^y under modulo m
 */
inline
long power(long x, long y, long m)
{
    if (y == 0)                                         // 基础情况 - Base case
        return 1;
    long p = power(x, y / 2, m) % m;                    // 递归计算 - Recursive calculation
    p = (p * p) % m;                                    // 平方 - Square

    return (y % 2 == 0) ? p : (x * p) % m;             // 根据y的奇偶性返回 - Return based on parity of y
}

/**
 * 计算模逆 - Calculate modular inverse
 * @param a 输入数 - Input number
 * @param m 模数 - Modulus
 * @return 返回a在模m下的逆 - Returns inverse of a under modulo m
 */
inline
long modInverse(long a, long m)
{
    return power(a, m - 2, m);                          // 使用费马小定理 - Using Fermat's little theorem
}

/**
 * 模除法 - Modular division
 * @param a 被除数 - Dividend
 * @param b 除数 - Divisor
 * @param mod 模数 - Modulus
 * @return 返回a/b在模mod下的结果 - Returns a/b under modulo mod
 */
inline
long div_mod(long a, long b, long mod = 65537){
    return (a*modInverse(b, mod)) % mod;                // 乘以模逆 - Multiply by modular inverse
}

/**
 * 获取比率、乘法并减法 - Get ratio, multiply and subtract
 * @param output 输出向量 - Output vector
 * @param input 输入向量 - Input vector
 * @param whichItem 哪个项目 - Which item
 * @param numToSolve 要求解的数量 - Number to solve
 * @param k 比率系数 - Ratio coefficient
 */
inline
void get_ratio_mult_and_subtract(vector<int>& output, const vector<int>& input, const int& whichItem, const int& numToSolve, int& k){
    vector<int> temp(input.size());                     // 临时向量 - Temporary vector
    if(k == -1){                                        // 如果k未设置 - If k is not set
        k = div_mod(output[whichItem], input[whichItem]); // 计算比率 - Calculate ratio
        mult_scalar_vec(temp, input, k);                // 标量乘法 - Scalar multiplication
        subtract_two_vec_inplace(output, temp);         // 就地减法 - In-place subtraction
    }
    else{                                               // 如果k已设置 - If k is set
        mult_scalar_vec(temp, input, k);                // 标量乘法 - Scalar multiplication
        subtract_two_vec_inplace(output, temp, numToSolve); // 部分减法 - Partial subtraction
    }
}

/**
 * 单个求解 - Single solve
 * @param a 系数 - Coefficient
 * @param toSolve 要求解的向量 - Vector to solve
 * @param mod 模数 - Modulus
 * @return 返回解向量 - Returns solution vector
 */
inline
vector<long> singleSolve(const long& a, const vector<int>& toSolve, long mod = 65537){
    long a_rev = modInverse(a, mod);                    // 计算a的模逆 - Calculate modular inverse of a
    vector<long> res(toSolve.size());                   // 结果向量 - Result vector
    for(size_t i = 0; i < toSolve.size(); i++){
        res[i] = ((long)toSolve[i] * a_rev) % 65537;    // 计算解 - Calculate solution
    }
    return res;                                         // 返回结果 - Return result
}

/**
 * 使用上述函数执行高斯消元 - Performs Gaussian elimination using the functions above
 * @param lhs 左侧方程组 - Left-hand side equations
 * @param rhs 右侧方程组 - Right-hand side equations
 * @param numToSolve 要求解的数量 - Number to solve
 * @return 返回解向量 - Returns solution vectors
 */
vector<vector<long>> equationSolving(vector<vector<int>>& lhs, vector<vector<int>>& rhs, const int& numToSolve = 306){
    vector<int> recoder(lhs[0].size(), -1);             // 记录器 - Recorder
    size_t counter = 0;                                 // 计数器 - Counter
    int rcd = 0;                                        // 记录值 - Recorded value

    // 高斯消元的前向消除阶段 - Forward elimination phase of Gaussian elimination
    while(counter < recoder.size()){
        // 寻找主元 - Find pivot
        for(size_t i = 0; i < lhs.size(); i++){
            if (lhs[i][counter] != 0){                  // 如果元素非零 - If element is non-zero
                if(find(recoder.begin(), recoder.end(), int(i)) != recoder.end()){ // 如果行已使用 - If row already used
                    continue;
                }
                recoder[counter] = i;                   // 记录主元行 - Record pivot row
                rcd = lhs[i][counter];                  // 记录主元值 - Record pivot value
                break;
            }
        }
        if(recoder[counter] == -1){                     // 如果没有找到主元 - If no pivot found
            cerr << "no solution" << endl;             // 无解 - No solution
            return vector<vector<long>>(0);
        }
        // 消除其他行 - Eliminate other rows
        for(size_t i = 0; i < lhs.size(); i++){
            if ((lhs[i][counter] != 0) && (lhs[i][counter] != rcd)) // 如果需要消除 - If elimination needed
            {
                int k = -1;                             // 比率系数 - Ratio coefficient
                get_ratio_mult_and_subtract(lhs[i], lhs[recoder[counter]], counter, numToSolve, k);
                get_ratio_mult_and_subtract(rhs[i], rhs[recoder[counter]], counter, numToSolve, k);
            }
        }
        counter++;                                      // 增加计数器 - Increment counter
    }

    // 回代求解 - Back substitution
    vector<vector<long>> res(recoder.size());           // 结果向量 - Result vector
    counter = 0;
    for(size_t i = 0; i < recoder.size(); i++){
        res[i] = singleSolve(lhs[recoder[counter]][counter], rhs[recoder[counter]]); // 求解单个方程 - Solve single equation
        counter++;
    }
    return res;                                         // 返回结果 - Return result
}