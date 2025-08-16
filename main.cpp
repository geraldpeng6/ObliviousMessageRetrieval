// 包含必要的头文件 - Include necessary header files
#include "include/PVWToBFVSeal.h"    // PVW到BFV的转换工具 - PVW to BFV conversion utilities
#include "include/SealUtils.h"        // SEAL库工具函数 - SEAL library utility functions
#include "include/retrieval.h"        // 检索相关函数 - Retrieval related functions
#include "include/client.h"           // 客户端相关函数 - Client related functions
#include "include/LoadAndSaveUtils.h" // 数据加载和保存工具 - Data loading and saving utilities
#include <NTL/BasicThreadPool.h>      // NTL线程池 - NTL thread pool
#include <NTL/ZZ.h>                   // NTL大整数类型 - NTL big integer type
#include <thread>                     // C++线程库 - C++ thread library

using namespace seal;

/**
 * 准备交易的正式函数 - Formal function for preparing transactions
 * @param pk PVW公钥 - PVW public key
 * @param numOfTransactions 交易总数 - Total number of transactions
 * @param pertinentMsgNum 相关消息数量 - Number of pertinent messages
 * @param params PVW参数 - PVW parameters
 * @param formultitest 是否用于多重测试 - Whether for multi-testing
 * @return 返回预期的消息向量 - Returns expected message vectors
 */
vector<vector<uint64_t>> preparinngTransactionsFormal(PVWpk& pk,
                                                    int numOfTransactions, int pertinentMsgNum, const PVWParam& params, bool formultitest = false){
    srand (time(NULL)); // 初始化随机数种子 - Initialize random seed

    vector<int> msgs(numOfTransactions);     // 消息标记数组 - Message marking array
    vector<vector<uint64_t>> ret;            // 返回结果 - Return result
    vector<int> zeros(params.ell, 0);        // 零向量 - Zero vector

    // 随机选择相关消息的索引 - Randomly select indices of pertinent messages
    for(int i = 0; i < pertinentMsgNum;){
        auto temp = rand() % numOfTransactions;
        while(msgs[temp]){                   // 确保不重复选择 - Ensure no duplicate selection
            temp = rand() % numOfTransactions;
        }
        msgs[temp] = 1;                      // 标记为相关消息 - Mark as pertinent message
        i++;
    }

    cout << "Expected Message Indices: ";   // 输出预期的消息索引 - Output expected message indices

    // 为每个交易生成线索 - Generate clues for each transaction
    for(int i = 0; i < numOfTransactions; i++){
        PVWCiphertext tempclue;              // 临时线索密文 - Temporary clue ciphertext
        if(msgs[i]){                         // 如果是相关消息 - If it's a pertinent message
            cout << i << " ";
            PVWEncPK(tempclue, zeros, pk, params);        // 使用公钥加密 - Encrypt with public key
            ret.push_back(loadDataSingle(i));             // 加载单个数据 - Load single data
            expectedIndices.push_back(uint64_t(i));       // 添加到预期索引 - Add to expected indices
        }
        else
        {
            auto sk2 = PVWGenerateSecretKey(params);       // 生成新的密钥 - Generate new secret key
            PVWEncSK(tempclue, zeros, sk2, params);       // 使用密钥加密 - Encrypt with secret key
        }

        saveClues(tempclue, i);              // 保存线索 - Save clues
    }
    cout << endl;
    return ret;                              // 返回结果 - Return result
}

/**
 * 阶段1：获取打包的SIC - Phase 1: obtaining packed SIC
 * @param SICPVW PVW密文向量 - PVW ciphertext vector
 * @param switchingKey 切换密钥 - Switching key
 * @param relin_keys 重线性化密钥 - Relinearization keys
 * @param gal_keys 伽罗瓦密钥 - Galois keys
 * @param degree 多项式度数 - Polynomial degree
 * @param context SEAL上下文 - SEAL context
 * @param params PVW参数 - PVW parameters
 * @param numOfTransactions 交易数量 - Number of transactions
 * @return 返回打包的密文 - Returns packed ciphertext
 */
Ciphertext serverOperations1obtainPackedSIC(vector<PVWCiphertext>& SICPVW, vector<Ciphertext> switchingKey, const RelinKeys& relin_keys,
                            const GaloisKeys& gal_keys, const size_t& degree, const SEALContext& context, const PVWParam& params, const int numOfTransactions){
    Evaluator evaluator(context);                    // 创建求值器 - Create evaluator

    vector<Ciphertext> packedSIC(params.ell);        // 打包的SIC向量 - Packed SIC vector
    // 计算B+AS的PVW优化版本 - Compute optimized PVW version of B+AS
    computeBplusASPVWOptimized(packedSIC, SICPVW, switchingKey, gal_keys, context, params);

    int rangeToCheck = 850;                          // 范围检查从[-rangeToCheck, rangeToCheck-1] - Range check from [-rangeToCheck, rangeToCheck-1]
    // 执行新的PVW范围检查 - Perform new PVW range check
    newRangeCheckPVW(packedSIC, rangeToCheck, relin_keys, degree, context, params);

    return packedSIC[0];                             // 返回第一个打包的SIC - Return first packed SIC
}

/**
 * 阶段2：检索操作的其余部分 - Phase 2: the rest of retrieval operations
 * @param lhs 左侧密文 - Left-hand side ciphertext
 * @param bipartite_map 二分图映射 - Bipartite map
 * @param rhs 右侧密文 - Right-hand side ciphertext
 * @param packedSIC 打包的SIC - Packed SIC
 * @param payload 载荷数据 - Payload data
 * @param relin_keys 重线性化密钥 - Relinearization keys
 * @param gal_keys 伽罗瓦密钥 - Galois keys
 * @param degree 多项式度数 - Polynomial degree
 * @param context SEAL上下文 - SEAL context
 * @param context2 第二个SEAL上下文 - Second SEAL context
 * @param params PVW参数 - PVW parameters
 * @param numOfTransactions 交易数量 - Number of transactions
 * @param counter 计数器 - Counter
 * @param payloadSize 载荷大小 - Payload size
 */
void serverOperations2therest(Ciphertext& lhs, vector<vector<int>>& bipartite_map, Ciphertext& rhs,
                        Ciphertext& packedSIC, const vector<vector<uint64_t>>& payload, const RelinKeys& relin_keys, const GaloisKeys& gal_keys,
                        const size_t& degree, const SEALContext& context, const SEALContext& context2, const PVWParam& params, const int numOfTransactions,
                        int& counter, const int payloadSize = 306){

    Evaluator evaluator(context);                    // 创建求值器 - Create evaluator
    int step = 32;                                   // 为节省内存，每次处理32条消息 - Process 32 messages at a time to save memory

    // 分批处理交易 - Process transactions in batches
    for(int i = counter; i < counter+numOfTransactions; i += step){
        vector<Ciphertext> expandedSIC;              // 扩展的SIC - Expanded SIC
        // 步骤1：扩展PV - Step 1: expand PV
        expandSIC(expandedSIC, packedSIC, gal_keys, int(degree), context, context2, step, i-counter);

        // 转换为NTT形式以提高效率，特别是对于最后两个步骤 - Transform to NTT form for better efficiency, especially for the last two steps
        for(size_t j = 0; j < expandedSIC.size(); j++)
            if(!expandedSIC[j].is_ntt_form())
                evaluator.transform_to_ntt_inplace(expandedSIC[j]);

        // 步骤2：确定性检索 - Step 2: deterministic retrieval
        deterministicIndexRetrieval(lhs, expandedSIC, context, degree, i);

        // 步骤3-4：乘以权重并打包 - Step 3-4: multiply weights and pack them
        // 以下两个步骤用于流式更新 - The following two steps are for streaming updates
        vector<vector<Ciphertext>> payloadUnpacked;  // 未打包的载荷 - Unpacked payload
        payloadRetrievalOptimizedwithWeights(payloadUnpacked, payload, bipartite_map_glb, weights_glb, expandedSIC, context, degree, i, i - counter);
        // 注意：如果重复次数已设定，这是流式更新唯一需要的步骤 - Note: if number of repetitions is already set, this is the only step needed for streaming updates
        payloadPackingOptimized(rhs, payloadUnpacked, bipartite_map_glb, degree, context, gal_keys, i);
    }
    // 如果是NTT形式，转换回普通形式 - If in NTT form, transform back to normal form
    if(lhs.is_ntt_form())
        evaluator.transform_from_ntt_inplace(lhs);
    if(rhs.is_ntt_form())
        evaluator.transform_from_ntt_inplace(rhs);

    counter += numOfTransactions;                    // 更新计数器 - Update counter
}

/**
 * 阶段2：OMR3的检索操作 - Phase 2: retrieving for OMR3
 * @param lhs 左侧密文向量 - Left-hand side ciphertext vector
 * @param lhsCounter 左侧计数器 - Left-hand side counter
 * @param bipartite_map 二分图映射 - Bipartite map
 * @param rhs 右侧密文 - Right-hand side ciphertext
 * @param packedSIC 打包的SIC - Packed SIC
 * @param payload 载荷数据 - Payload data
 * @param relin_keys 重线性化密钥 - Relinearization keys
 * @param gal_keys 伽罗瓦密钥 - Galois keys
 * @param public_key 公钥 - Public key
 * @param degree 多项式度数 - Polynomial degree
 * @param context SEAL上下文 - SEAL context
 * @param context2 第二个SEAL上下文 - Second SEAL context
 * @param params PVW参数 - PVW parameters
 * @param numOfTransactions 交易数量 - Number of transactions
 * @param counter 计数器 - Counter
 * @param payloadSize 载荷大小 - Payload size
 */
void serverOperations3therest(vector<vector<Ciphertext>>& lhs, vector<Ciphertext>& lhsCounter, vector<vector<int>>& bipartite_map, Ciphertext& rhs,
                        Ciphertext& packedSIC, const vector<vector<uint64_t>>& payload, const RelinKeys& relin_keys, const GaloisKeys& gal_keys, const PublicKey& public_key,
                        const size_t& degree, const SEALContext& context, const SEALContext& context2, const PVWParam& params, const int numOfTransactions,
                        int& counter, const int payloadSize = 306){

    Evaluator evaluator(context);                    // 创建求值器 - Create evaluator

    int step = 32;                                   // 批处理大小 - Batch size
    // 分批处理交易 - Process transactions in batches
    for(int i = counter; i < counter+numOfTransactions; i += step){
        // 步骤1：扩展PV - Step 1: expand PV
        vector<Ciphertext> expandedSIC;              // 扩展的SIC - Expanded SIC
        expandSIC(expandedSIC, packedSIC, gal_keys, int(degree), context, context2, step, i-counter);
        // 转换为NTT形式以提高所有后续步骤的效率 - Transform to NTT form for better efficiency for all following steps
        for(size_t j = 0; j < expandedSIC.size(); j++)
            if(!expandedSIC[j].is_ntt_form())
                evaluator.transform_to_ntt_inplace(expandedSIC[j]);

        // 步骤2：随机化检索 - Step 2: randomized retrieval
        randomizedIndexRetrieval(lhs, lhsCounter, expandedSIC, context2, public_key, i, degree, C_glb);

        // 步骤3-4：乘以权重并打包 - Step 3-4: multiply weights and pack them
        // 以下两个步骤用于流式更新 - The following two steps are for streaming updates
        vector<vector<Ciphertext>> payloadUnpacked;  // 未打包的载荷 - Unpacked payload
        payloadRetrievalOptimizedwithWeights(payloadUnpacked, payload, bipartite_map_glb, weights_glb, expandedSIC, context, degree, i, i-counter);
        // 注意：如果重复次数已设定，这是流式更新唯一需要的步骤 - Note: if number of repetitions is already set, this is the only step needed for streaming updates
        payloadPackingOptimized(rhs, payloadUnpacked, bipartite_map_glb, degree, context, gal_keys, i);
    }
    // 将所有密文从NTT形式转换回普通形式 - Transform all ciphertexts from NTT form back to normal form
    for(size_t i = 0; i < lhs.size(); i++){
            evaluator.transform_from_ntt_inplace(lhs[i][0]);
            evaluator.transform_from_ntt_inplace(lhs[i][1]);
            evaluator.transform_from_ntt_inplace(lhsCounter[i]);
    }
    if(rhs.is_ntt_form())
        evaluator.transform_from_ntt_inplace(rhs);

    counter += numOfTransactions;                    // 更新计数器 - Update counter
}

/**
 * 接收方解码函数 - Receiver decoding function
 * @param lhsEnc 加密的左侧数据 - Encrypted left-hand side data
 * @param bipartite_map 二分图映射 - Bipartite map
 * @param rhsEnc 加密的右侧数据 - Encrypted right-hand side data
 * @param degree 多项式度数 - Polynomial degree
 * @param secret_key 密钥 - Secret key
 * @param context SEAL上下文 - SEAL context
 * @param numOfTransactions 交易数量 - Number of transactions
 * @param seed 随机种子 - Random seed
 * @param payloadUpperBound 载荷上界 - Payload upper bound
 * @param payloadSize 载荷大小 - Payload size
 * @return 返回解码后的数据 - Returns decoded data
 */
vector<vector<long>> receiverDecoding(Ciphertext& lhsEnc, vector<vector<int>>& bipartite_map, Ciphertext& rhsEnc,
                        const size_t& degree, const SecretKey& secret_key, const SEALContext& context, const int numOfTransactions, int seed = 3,
                        const int payloadUpperBound = 306, const int payloadSize = 306){

    // 1. 查找相关索引 - Find pertinent indices
    map<int, int> pertinentIndices;              // 相关索引映射 - Pertinent indices map
    decodeIndices(pertinentIndices, lhsEnc, numOfTransactions, degree, secret_key, context);
    // 输出找到的所有索引 - Print out all the indices found
    for (map<int, int>::iterator it = pertinentIndices.begin(); it != pertinentIndices.end(); it++)
    {
        std::cout << it->first << " ";
    }
    cout << std::endl;

    // 2. 构建右侧方程 - Forming right-hand side
    vector<vector<int>> rhs;                     // 右侧数据 - Right-hand side data
    formRhs(rhs, rhsEnc, secret_key, degree, context, OMRtwoM);

    // 3. 构建左侧方程 - Forming left-hand side
    vector<vector<int>> lhs;                     // 左侧数据 - Left-hand side data
    formLhsWeights(lhs, pertinentIndices, bipartite_map_glb, weights_glb, 0, OMRtwoM);

    // 4. 求解方程 - Solving equation
    auto newrhs = equationSolving(lhs, rhs, payloadSize);

    return newrhs;                               // 返回新的右侧结果 - Return new right-hand side result
}

/**
 * OMR3的接收方解码函数 - Receiver decoding function for OMR3
 * @param lhsEnc 加密的左侧数据向量 - Encrypted left-hand side data vector
 * @param lhsCounter 左侧计数器 - Left-hand side counter
 * @param bipartite_map 二分图映射 - Bipartite map
 * @param rhsEnc 加密的右侧数据 - Encrypted right-hand side data
 * @param degree 多项式度数 - Polynomial degree
 * @param secret_key 密钥 - Secret key
 * @param context SEAL上下文 - SEAL context
 * @param numOfTransactions 交易数量 - Number of transactions
 * @param seed 随机种子 - Random seed
 * @param payloadUpperBound 载荷上界 - Payload upper bound
 * @param payloadSize 载荷大小 - Payload size
 * @return 返回解码后的数据 - Returns decoded data
 */
vector<vector<long>> receiverDecodingOMR3(vector<vector<Ciphertext>>& lhsEnc, vector<Ciphertext>& lhsCounter, vector<vector<int>>& bipartite_map, Ciphertext& rhsEnc,
                        const size_t& degree, const SecretKey& secret_key, const SEALContext& context, const int numOfTransactions, int seed = 3,
                        const int payloadUpperBound = 306, const int payloadSize = 306){
    // 1. 查找相关索引 - Find pertinent indices
    map<int, int> pertinentIndices;              // 相关索引映射 - Pertinent indices map
    decodeIndicesRandom(pertinentIndices, lhsEnc, lhsCounter, degree, secret_key, context);
    // 输出找到的所有索引 - Print out all the indices found
    for (map<int, int>::iterator it = pertinentIndices.begin(); it != pertinentIndices.end(); it++)
    {
        std::cout << it->first << " ";
    }
    cout << std::endl;

    // 2. 构建右侧方程 - Forming right-hand side
    vector<vector<int>> rhs;                     // 右侧方程组 - Right-hand side equations
    formRhs(rhs, rhsEnc, secret_key, degree, context, OMRthreeM);

    // 3. 构建左侧方程 - Forming left-hand side
    vector<vector<int>> lhs;                     // 左侧方程组 - Left-hand side equations
    formLhsWeights(lhs, pertinentIndices, bipartite_map_glb, weights_glb, 0, OMRthreeM);

    // 4. 求解方程 - Solving equation
    auto newrhs = equationSolving(lhs, rhs, payloadSize);

    return newrhs;                               // 返回新的右侧结果 - Return new right-hand side result
}

/**
 * 检查结果是否符合预期 - Check whether the result is as expected
 * @param expected 预期结果 - Expected results
 * @param res 实际结果 - Actual results
 * @return 如果结果匹配返回true - Returns true if results match
 */
bool checkRes(vector<vector<uint64_t>> expected, vector<vector<long>> res){
    // 遍历所有预期结果 - Iterate through all expected results
    for(size_t i = 0; i < expected.size(); i++){
        bool flag = false;                       // 匹配标志 - Match flag
        // 在实际结果中查找匹配项 - Search for matches in actual results
        for(size_t j = 0; j < res.size(); j++){
            if(expected[i][0] == uint64_t(res[j][0])){  // 如果索引匹配 - If indices match
                if(expected[i].size() != res[j].size())  // 检查长度是否相同 - Check if lengths are the same
                {
                    cerr << "expected and res length not the same" << endl;
                    return false;
                }
                // 逐个比较元素 - Compare elements one by one
                for(size_t k = 1; k < res[j].size(); k++){
                    if(expected[i][k] != uint64_t(res[j][k]))
                        break;
                    if(k == res[j].size() - 1){  // 如果所有元素都匹配 - If all elements match
                        flag = true;
                    }
                }
            }
        }
        if(!flag)                                // 如果没有找到匹配项 - If no match found
            return false;
    }
    return true;                                 // 所有预期结果都找到匹配项 - All expected results found matches
}

/**
 * 检查OMD检测密钥大小 - Check OMD detection key size
 * 我们正在做：- We are:
 *      1. 将PVW私钥打包到ell个密文中 - Packing PVW sk into ell ciphertexts
 *      2. 在SEAL中使用种子模式 - Using seed mode in SEAL
 */
void OMDlevelspecificDetectKeySize(){
    auto params = PVWParam(450, 65537, 1.3, 16000, 4);  // PVW参数设置 - PVW parameter setup
    auto sk = PVWGenerateSecretKey(params);              // 生成PVW私钥 - Generate PVW secret key
    cout << "Finishing generating sk for PVW cts\n";
    EncryptionParameters parms(scheme_type::bfv);        // BFV加密参数 - BFV encryption parameters
    size_t poly_modulus_degree = poly_modulus_degree_glb; // 多项式模数度 - Polynomial modulus degree
    parms.set_poly_modulus_degree(poly_modulus_degree);
    // 创建系数模数 - Create coefficient modulus
    auto coeff_modulus = CoeffModulus::Create(poly_modulus_degree, { 28,
                                                                            39, 60, 60, 60,
                                                                            60, 60, 60, 60, 60, 60,
                                                                            32, 30, 60 });
    parms.set_coeff_modulus(coeff_modulus);
    parms.set_plain_modulus(65537);                      // 设置明文模数 - Set plain modulus

	prng_seed_type seed;                                 // 伪随机数生成器种子 - PRNG seed
    for (auto &i : seed)
    {
        i = random_uint64();                             // 生成随机种子 - Generate random seed
    }
    auto rng = make_shared<Blake2xbPRNGFactory>(Blake2xbPRNGFactory(seed));
    parms.set_random_generator(rng);                     // 设置随机数生成器 - Set random generator

    SEALContext context(parms, true, sec_level_type::none); // 创建SEAL上下文 - Create SEAL context
    print_parameters(context);                           // 打印参数 - Print parameters
    KeyGenerator keygen(context);                        // 密钥生成器 - Key generator
    SecretKey secret_key = keygen.secret_key();          // 私钥 - Secret key
    PublicKey public_key;                                // 公钥 - Public key
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;                                // 重线性化密钥 - Relinearization keys
    Encryptor encryptor(context, public_key);            // 加密器 - Encryptor
    Evaluator evaluator(context);                        // 求值器 - Evaluator
    Decryptor decryptor(context, secret_key);            // 解密器 - Decryptor
    BatchEncoder batch_encoder(context);                 // 批编码器 - Batch encoder
    GaloisKeys gal_keys;                                 // 伽罗瓦密钥 - Galois keys

    // 创建可序列化的密钥 - Create serializable keys
    seal::Serializable<PublicKey> pk = keygen.create_public_key();
	seal::Serializable<RelinKeys> rlk = keygen.create_relin_keys();
	stringstream streamPK, streamRLK, streamRTK;        // 数据流 - Data streams
    auto reskeysize = pk.save(streamPK);                 // 保存公钥并计算大小 - Save public key and calculate size
	reskeysize += rlk.save(streamRLK);                   // 保存重线性化密钥 - Save relinearization keys
	reskeysize += keygen.create_galois_keys(vector<int>({1})).save(streamRTK); // 保存伽罗瓦密钥 - Save Galois keys

    // 加载密钥 - Load keys
    public_key.load(context, streamPK);
    relin_keys.load(context, streamRLK);
    gal_keys.load(context, streamRTK);
	// 生成打包的切换密钥 - Generate packed switching keys
	vector<seal::Serializable<Ciphertext>>  switchingKeypacked = genSwitchingKeyPVWPacked(context, poly_modulus_degree, public_key, secret_key, sk, params);
	stringstream data_stream;                            // 数据流 - Data stream
    // 计算切换密钥大小 - Calculate switching key size
    for(size_t i = 0; i < switchingKeypacked.size(); i++){
        reskeysize += switchingKeypacked[i].save(data_stream);
    }
    cout << "Detection Key Size: " << reskeysize << " bytes" << endl; // 输出检测密钥大小 - Output detection key size
}

/**
 * 检查OMR检测密钥大小 - Check OMR detection key size
 * 我们正在做：- We are:
 *      1. 将PVW私钥打包到ell个密文中 - Packing PVW sk into ell ciphertexts
 *      2. 使用级别特定的旋转密钥 - Use level-specific rotation keys
 *      3. 在SEAL中使用种子模式 - Using seed mode in SEAL
 */
void levelspecificDetectKeySize(){
    auto params = PVWParam(450, 65537, 1.3, 16000, 4);  // PVW参数设置 - PVW parameter setup
    auto sk = PVWGenerateSecretKey(params);              // 生成PVW私钥 - Generate PVW secret key
    cout << "Finishing generating sk for PVW cts\n";

    EncryptionParameters parms(scheme_type::bfv);        // BFV加密参数 - BFV encryption parameters
    size_t poly_modulus_degree = poly_modulus_degree_glb; // 多项式模数度 - Polynomial modulus degree
    auto degree = poly_modulus_degree;                   // 度数 - Degree
    parms.set_poly_modulus_degree(poly_modulus_degree);
    // 创建系数模数 - Create coefficient modulus
    auto coeff_modulus = CoeffModulus::Create(poly_modulus_degree, { 28,
                                                                            39, 60, 60, 60, 60,
                                                                            60, 60, 60, 60, 60, 60,
                                                                            32, 30, 60 });
    parms.set_coeff_modulus(coeff_modulus);
    parms.set_plain_modulus(65537);


	prng_seed_type seed;
    for (auto &i : seed)
    {
        i = random_uint64();
    }
    auto rng = make_shared<Blake2xbPRNGFactory>(Blake2xbPRNGFactory(seed));
    parms.set_random_generator(rng);

    SEALContext context(parms, true, sec_level_type::none);
    print_parameters(context); 
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    BatchEncoder batch_encoder(context);
    GaloisKeys gal_keys;

    vector<int> steps = {0};
    for(int i = 1; i < int(poly_modulus_degree/2); i *= 2){
	    steps.push_back(i);
    }

    stringstream lvlRTK, lvlRTK2;
    /////////////////////////////////////// Level specific keys
    vector<Modulus> coeff_modulus_next = coeff_modulus;
    coeff_modulus_next.erase(coeff_modulus_next.begin() + 3, coeff_modulus_next.end()-1);
    EncryptionParameters parms_next = parms;
    parms_next.set_coeff_modulus(coeff_modulus_next);
    parms_next.set_random_generator(rng);
    SEALContext context_next = SEALContext(parms_next, true, sec_level_type::none);

    SecretKey sk_next;
    sk_next.data().resize(coeff_modulus_next.size() * degree);
    sk_next.parms_id() = context_next.key_parms_id();
    util::set_poly(secret_key.data().data(), degree, coeff_modulus_next.size() - 1, sk_next.data().data());
    util::set_poly(
        secret_key.data().data() + degree * (coeff_modulus.size() - 1), degree, 1,
        sk_next.data().data() + degree * (coeff_modulus_next.size() - 1));
    KeyGenerator keygen_next(context_next, sk_next); 
    vector<int> steps_next = {0,1};
    auto reskeysize = keygen_next.create_galois_keys(steps_next).save(lvlRTK);
        //////////////////////////////////////
    vector<Modulus> coeff_modulus_last = coeff_modulus;
    coeff_modulus_last.erase(coeff_modulus_last.begin() + 2, coeff_modulus_last.end()-1);
    EncryptionParameters parms_last = parms;
    parms_last.set_coeff_modulus(coeff_modulus_last);
    parms_last.set_random_generator(rng);
    SEALContext context_last = SEALContext(parms_last, true, sec_level_type::none);

    SecretKey sk_last;
    sk_last.data().resize(coeff_modulus_last.size() * degree);
    sk_last.parms_id() = context_last.key_parms_id();
    util::set_poly(secret_key.data().data(), degree, coeff_modulus_last.size() - 1, sk_last.data().data());
    util::set_poly(
        secret_key.data().data() + degree * (coeff_modulus.size() - 1), degree, 1,
        sk_last.data().data() + degree * (coeff_modulus_last.size() - 1));
    KeyGenerator keygen_last(context_last, sk_last); 
    reskeysize += keygen_last.create_galois_keys(steps).save(lvlRTK2);
    //////////////////////////////////////

    seal::Serializable<PublicKey> pk = keygen.create_public_key();
	seal::Serializable<RelinKeys> rlk = keygen.create_relin_keys();
	stringstream streamPK, streamRLK, streamRTK;
    reskeysize += pk.save(streamPK);
	reskeysize += rlk.save(streamRLK);
	reskeysize += keygen.create_galois_keys(vector<int>({1})).save(streamRTK);

    public_key.load(context, streamPK);
    relin_keys.load(context, streamRLK);
    gal_keys.load(context, streamRTK); 
	vector<seal::Serializable<Ciphertext>>  switchingKeypacked = genSwitchingKeyPVWPacked(context, poly_modulus_degree, public_key, secret_key, sk, params);
	stringstream data_stream;
    for(size_t i = 0; i < switchingKeypacked.size(); i++){
        reskeysize += switchingKeypacked[i].save(data_stream);
    }
    cout << "Detection Key Size: " << reskeysize << " bytes" << endl;
}

void OMD1p(){

    size_t poly_modulus_degree = poly_modulus_degree_glb;

    int numOfTransactions = numOfTransactions_glb;
    createDatabase(numOfTransactions, 306); // one time; note that this 306 represents 612 bytes because each slot can contain 2 bytes
    cout << "Finishing createDatabase\n";

    // step 1. generate PVW sk 
    // recipient side
    auto params = PVWParam(450, 65537, 1.3, 16000, 4); 
    auto sk = PVWGenerateSecretKey(params);
    auto pk = PVWGeneratePublicKey(params, sk);
    cout << "Finishing generating sk for PVW cts\n";

    // step 2. prepare transactions
    auto expected = preparinngTransactionsFormal(pk, numOfTransactions, num_of_pertinent_msgs_glb,  params);
    cout << expected.size() << " pertinent msg: Finishing preparing messages\n";



    // step 3. generate detection key
    // recipient side
    EncryptionParameters parms(scheme_type::bfv);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    auto coeff_modulus = CoeffModulus::Create(poly_modulus_degree, { 28, 
                                                                            39, 60, 60, 60, 
                                                                            60, 60, 60, 60, 60, 60,
                                                                            32, 30, 60 });
    parms.set_coeff_modulus(coeff_modulus);
    parms.set_plain_modulus(65537);


	prng_seed_type seed;
    for (auto &i : seed)
    {
        i = random_uint64();
    }
    auto rng = make_shared<Blake2xbPRNGFactory>(Blake2xbPRNGFactory(seed));
    parms.set_random_generator(rng);

    SEALContext context(parms, true, sec_level_type::none);
    print_parameters(context); 
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    BatchEncoder batch_encoder(context);


    vector<Ciphertext> switchingKey;
    Ciphertext packedSIC;
    switchingKey.resize(params.ell);
    // Generated BFV ciphertexts encrypting PVW secret keys
    genSwitchingKeyPVWPacked(switchingKey, context, poly_modulus_degree, public_key, secret_key, sk, params);
    
    vector<vector<PVWCiphertext>> SICPVW_multicore(numcores);
    vector<vector<vector<uint64_t>>> payload_multicore(numcores);
    vector<int> counter(numcores);

    GaloisKeys gal_keys;
    vector<int> stepsfirst = {1}; 
    // only one rot key is needed for full level
    keygen.create_galois_keys(stepsfirst, gal_keys);

    cout << "Finishing generating detection keys\n";

    vector<vector<Ciphertext>> packedSICfromPhase1(numcores,vector<Ciphertext>(numOfTransactions/numcores/poly_modulus_degree)); // Assume numOfTransactions/numcores/poly_modulus_degree is integer, pad if needed

    NTL::SetNumThreads(numcores);
    SecretKey secret_key_blank;

    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;
    time_start = chrono::high_resolution_clock::now();

    MemoryPoolHandle my_pool = MemoryPoolHandle::New();
    auto old_prof = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool)));
    NTL_EXEC_RANGE(numcores, first, last);
    for(int i = first; i < last; i++){
        counter[i] = numOfTransactions/numcores*i;
        
        size_t j = 0;
        while(j < numOfTransactions/numcores/poly_modulus_degree){
            cout << "OMD, Batch " << j << endl;
            loadClues(SICPVW_multicore[i], counter[i], counter[i]+poly_modulus_degree, params);
            packedSICfromPhase1[i][j] = serverOperations1obtainPackedSIC(SICPVW_multicore[i], switchingKey, relin_keys, gal_keys,
                                                            poly_modulus_degree, context, params, poly_modulus_degree);
            j++;
            counter[i] += poly_modulus_degree;
            SICPVW_multicore[i].clear();
        }
        
    }
    NTL_EXEC_RANGE_END;
    MemoryManager::SwitchProfile(std::move(old_prof));

    int determinCounter = 0;
    Ciphertext res;
    for(size_t i = 0; i < packedSICfromPhase1.size(); i++){
        for(size_t j = 0; j < packedSICfromPhase1[i].size(); j++){
            Plaintext plain_matrix;
            vector<uint64_t> pod_matrix(poly_modulus_degree, 1 << determinCounter); 
            batch_encoder.encode(pod_matrix, plain_matrix);
            if((i == 0) && (j == 0)){
                evaluator.multiply_plain(packedSICfromPhase1[i][j], plain_matrix, res);
            } else {
                evaluator.multiply_plain_inplace(packedSICfromPhase1[i][j], plain_matrix);
                evaluator.add_inplace(res, packedSICfromPhase1[i][j]);
            }
            determinCounter++;
        }
    }

    while(context.last_parms_id() != res.parms_id()){
            evaluator.mod_switch_to_next_inplace(res);
        }

    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "\nDetector runnimg time: " << time_diff.count() << "us." << "\n";

    // step 5. receiver decoding
    time_start = chrono::high_resolution_clock::now();
    auto realres = decodeIndicesOMD(res, numOfTransactions, poly_modulus_degree, secret_key, context);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "\nRecipient runnimg time: " << time_diff.count() << "us." << "\n";

    bool allflags = true;
    for(size_t i = 0; i < expectedIndices.size(); i++){
        bool flag = false;
        for(size_t j = 0; j < realres.size(); j++){
            if(expectedIndices[i] == realres[j])
            {
                flag = true;
                break;
            }
        }
        if(!flag){
            cout << expectedIndices[i] <<" not found" << endl;
            allflags = false;
        }
    }

    if(allflags)
        cout << "Result is correct!" << endl;
    else
        cout << "Overflow" << endl;
    
    for(size_t i = 0; i < res.size(); i++){

    }
    
}

void OMR2(){

    size_t poly_modulus_degree = poly_modulus_degree_glb;

    int numOfTransactions = numOfTransactions_glb;
    createDatabase(numOfTransactions, 306); 
    cout << "Finishing createDatabase\n";

    // step 1. generate PVW sk 
    // recipient side
    auto params = PVWParam(450, 65537, 1.3, 16000, 4); 
    auto sk = PVWGenerateSecretKey(params);
    auto pk = PVWGeneratePublicKey(params, sk);
    cout << "Finishing generating sk for PVW cts\n";

    // step 2. prepare transactions
    auto expected = preparinngTransactionsFormal(pk, numOfTransactions, num_of_pertinent_msgs_glb,  params);
    cout << expected.size() << " pertinent msg: Finishing preparing messages\n";

    // step 3. generate detection key
    // recipient side
    EncryptionParameters parms(scheme_type::bfv);
    auto degree = poly_modulus_degree;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    auto coeff_modulus = CoeffModulus::Create(poly_modulus_degree, { 28, 
                                                                            39, 60, 60, 60, 60, 
                                                                            60, 60, 60, 60, 60, 60,
                                                                            32, 30, 60 });
    parms.set_coeff_modulus(coeff_modulus);
    parms.set_plain_modulus(65537);


	prng_seed_type seed;
    for (auto &i : seed)
    {
        i = random_uint64();
    }
    auto rng = make_shared<Blake2xbPRNGFactory>(Blake2xbPRNGFactory(seed));
    parms.set_random_generator(rng);

    SEALContext context(parms, true, sec_level_type::none);
    print_parameters(context); 
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    BatchEncoder batch_encoder(context);


    vector<Ciphertext> switchingKey;
    Ciphertext packedSIC;
    switchingKey.resize(params.ell);
    genSwitchingKeyPVWPacked(switchingKey, context, poly_modulus_degree, public_key, secret_key, sk, params);
    
    vector<vector<PVWCiphertext>> SICPVW_multicore(numcores);
    vector<vector<vector<uint64_t>>> payload_multicore(numcores);
    vector<int> counter(numcores);

    GaloisKeys gal_keys;
    vector<int> stepsfirst = {1};
    // only one rot key is needed for full level
    keygen.create_galois_keys(stepsfirst, gal_keys);

    /////////////////////////////////////////////////////////////// Rot Key gen
    vector<int> steps = {0};
    for(int i = 1; i < int(poly_modulus_degree/2); i *= 2){
	    steps.push_back(i);
    }

    cout << "Finishing generating detection keys\n";

    /////////////////////////////////////// Level specific keys
    vector<Modulus> coeff_modulus_next = coeff_modulus;
    coeff_modulus_next.erase(coeff_modulus_next.begin() + 4, coeff_modulus_next.end()-1);
    EncryptionParameters parms_next = parms;
    parms_next.set_coeff_modulus(coeff_modulus_next);
    SEALContext context_next = SEALContext(parms_next, true, sec_level_type::none);

    SecretKey sk_next;
    sk_next.data().resize(coeff_modulus_next.size() * degree);
    sk_next.parms_id() = context_next.key_parms_id();
    util::set_poly(secret_key.data().data(), degree, coeff_modulus_next.size() - 1, sk_next.data().data());
    util::set_poly(
        secret_key.data().data() + degree * (coeff_modulus.size() - 1), degree, 1,
        sk_next.data().data() + degree * (coeff_modulus_next.size() - 1));
    KeyGenerator keygen_next(context_next, sk_next); 
    vector<int> steps_next = {0,1};
    keygen_next.create_galois_keys(steps_next, gal_keys_next);
        //////////////////////////////////////
    vector<Modulus> coeff_modulus_last = coeff_modulus;
    coeff_modulus_last.erase(coeff_modulus_last.begin() + 2, coeff_modulus_last.end()-1);
    EncryptionParameters parms_last = parms;
    parms_last.set_coeff_modulus(coeff_modulus_last);
    SEALContext context_last = SEALContext(parms_last, true, sec_level_type::none);

    SecretKey sk_last;
    sk_last.data().resize(coeff_modulus_last.size() * degree);
    sk_last.parms_id() = context_last.key_parms_id();
    util::set_poly(secret_key.data().data(), degree, coeff_modulus_last.size() - 1, sk_last.data().data());
    util::set_poly(
        secret_key.data().data() + degree * (coeff_modulus.size() - 1), degree, 1,
        sk_last.data().data() + degree * (coeff_modulus_last.size() - 1));
    KeyGenerator keygen_last(context_last, sk_last); 
    keygen_last.create_galois_keys(steps, gal_keys_last);
    //////////////////////////////////////

    vector<vector<Ciphertext>> packedSICfromPhase1(numcores,vector<Ciphertext>(numOfTransactions/numcores/poly_modulus_degree)); // Assume numOfTransactions/numcores/poly_modulus_degree is integer, pad if needed

    NTL::SetNumThreads(numcores);
    SecretKey secret_key_blank;

    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;
    time_start = chrono::high_resolution_clock::now();

    MemoryPoolHandle my_pool = MemoryPoolHandle::New();
    auto old_prof = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool)));
    NTL_EXEC_RANGE(numcores, first, last);
    for(int i = first; i < last; i++){
        counter[i] = numOfTransactions/numcores*i;
        
        size_t j = 0;
        while(j < numOfTransactions/numcores/poly_modulus_degree){
            if(!i)
                cout << "Phase 1, Core " << i << ", Batch " << j << endl;
            loadClues(SICPVW_multicore[i], counter[i], counter[i]+poly_modulus_degree, params);
            packedSICfromPhase1[i][j] = serverOperations1obtainPackedSIC(SICPVW_multicore[i], switchingKey, relin_keys, gal_keys,
                                                            poly_modulus_degree, context, params, poly_modulus_degree);
            j++;
            counter[i] += poly_modulus_degree;
            SICPVW_multicore[i].clear();
        }
        
    }
    NTL_EXEC_RANGE_END;
    MemoryManager::SwitchProfile(std::move(old_prof));

    // step 4. detector operations
    vector<Ciphertext> lhs_multi(numcores), rhs_multi(numcores);
    vector<vector<vector<int>>> bipartite_map(numcores);

    bipartiteGraphWeightsGeneration(bipartite_map_glb, weights_glb, numOfTransactions,OMRtwoM,repeatition_glb,seed_glb);

    NTL_EXEC_RANGE(numcores, first, last);
    for(int i = first; i < last; i++){
        MemoryPoolHandle my_pool = MemoryPoolHandle::New();
        auto old_prof = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool)));
        size_t j = 0;
        counter[i] = numOfTransactions/numcores*i;

        while(j < numOfTransactions/numcores/poly_modulus_degree){
            if(!i)
                cout << "Phase 2-3, Core " << i << ", Batch " << j << endl;
            loadData(payload_multicore[i], counter[i], counter[i]+poly_modulus_degree);
            Ciphertext templhs, temprhs;
            serverOperations2therest(templhs, bipartite_map[i], temprhs,
                            packedSICfromPhase1[i][j], payload_multicore[i], relin_keys, gal_keys_next,
                            poly_modulus_degree, context_next, context_last, params, poly_modulus_degree, counter[i]);
            if(j == 0){
                lhs_multi[i] = templhs;
                rhs_multi[i] = temprhs;
            } else {
                evaluator.add_inplace(lhs_multi[i], templhs);
                evaluator.add_inplace(rhs_multi[i], temprhs);
            }
            j++;
            payload_multicore[i].clear();
        }
        
        MemoryManager::SwitchProfile(std::move(old_prof));
    }
    NTL_EXEC_RANGE_END;

    for(int i = 1; i < numcores; i++){
        evaluator.add_inplace(lhs_multi[0], lhs_multi[i]);
        evaluator.add_inplace(rhs_multi[0], rhs_multi[i]);
    }

    while(context.last_parms_id() != lhs_multi[0].parms_id()){
            evaluator.mod_switch_to_next_inplace(rhs_multi[0]);
            evaluator.mod_switch_to_next_inplace(lhs_multi[0]);
        }

    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "\nDetector runnimg time: " << time_diff.count() << "us." << "\n";

    stringstream data_streamdg, data_streamdg2;
    cout << "Digest size: " << rhs_multi[0].save(data_streamdg) + lhs_multi[0].save(data_streamdg2) << " bytes" << endl;

    // step 5. receiver decoding
    bipartiteGraphWeightsGeneration(bipartite_map_glb, weights_glb, numOfTransactions,OMRtwoM,repeatition_glb,seed_glb);
    time_start = chrono::high_resolution_clock::now();
    auto res = receiverDecoding(lhs_multi[0], bipartite_map[0], rhs_multi[0],
                        poly_modulus_degree, secret_key, context, numOfTransactions);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "\nRecipient runnimg time: " << time_diff.count() << "us." << "\n";

    if(checkRes(expected, res))
        cout << "Result is correct!" << endl;
    else
        cout << "Overflow" << endl;
}

void OMR3(){

    size_t poly_modulus_degree = poly_modulus_degree_glb;

    int numOfTransactions = numOfTransactions_glb;
    createDatabase(numOfTransactions, 306); 
    cout << "Finishing createDatabase\n";

    // step 1. generate PVW sk
    // recipient side
    auto params = PVWParam(450, 65537, 1.3, 16000, 4); 
    auto sk = PVWGenerateSecretKey(params);
    auto pk = PVWGeneratePublicKey(params, sk);
    cout << "Finishing generating sk for PVW cts\n";

    // step 2. prepare transactions
    auto expected = preparinngTransactionsFormal(pk, numOfTransactions, num_of_pertinent_msgs_glb,  params);
    cout << expected.size() << " pertinent msg: Finishing preparing messages\n";



    // step 3. generate detection key
    // recipient side
    EncryptionParameters parms(scheme_type::bfv);
    auto degree = poly_modulus_degree;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    auto coeff_modulus = CoeffModulus::Create(poly_modulus_degree, { 28, 
                                                                            39, 60, 60, 60, 60, 
                                                                            60, 60, 60, 60, 60, 60,
                                                                            32, 30, 60 });
    parms.set_coeff_modulus(coeff_modulus);
    parms.set_plain_modulus(65537);


	prng_seed_type seed;
    for (auto &i : seed)
    {
        i = random_uint64();
    }
    auto rng = make_shared<Blake2xbPRNGFactory>(Blake2xbPRNGFactory(seed));
    parms.set_random_generator(rng);

    SEALContext context(parms, true, sec_level_type::none);
    print_parameters(context); 
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    BatchEncoder batch_encoder(context);


    vector<Ciphertext> switchingKey;
    Ciphertext packedSIC;
    switchingKey.resize(params.ell);
    genSwitchingKeyPVWPacked(switchingKey, context, poly_modulus_degree, public_key, secret_key, sk, params);
    
    vector<vector<PVWCiphertext>> SICPVW_multicore(numcores);
    vector<vector<vector<uint64_t>>> payload_multicore(numcores);
    vector<int> counter(numcores);

    GaloisKeys gal_keys;
    vector<int> stepsfirst = {1};
    keygen.create_galois_keys(stepsfirst, gal_keys);

    /////////////////////////////////////////////////////////////// Rot Key gen
    vector<int> steps = {0};
    for(int i = 1; i < int(poly_modulus_degree/2); i *= 2){
	    steps.push_back(i);
    }

    cout << "Finishing generating detection keys\n";

    /////////////////////////////////////// Level specific keys
    vector<Modulus> coeff_modulus_next = coeff_modulus;
    coeff_modulus_next.erase(coeff_modulus_next.begin() + 4, coeff_modulus_next.end()-1);
    EncryptionParameters parms_next = parms;
    parms_next.set_coeff_modulus(coeff_modulus_next);
    SEALContext context_next = SEALContext(parms_next, true, sec_level_type::none);

    SecretKey sk_next;
    sk_next.data().resize(coeff_modulus_next.size() * degree);
    sk_next.parms_id() = context_next.key_parms_id();
    util::set_poly(secret_key.data().data(), degree, coeff_modulus_next.size() - 1, sk_next.data().data());
    util::set_poly(
        secret_key.data().data() + degree * (coeff_modulus.size() - 1), degree, 1,
        sk_next.data().data() + degree * (coeff_modulus_next.size() - 1));
    KeyGenerator keygen_next(context_next, sk_next); 
    vector<int> steps_next = {0,1};
    keygen_next.create_galois_keys(steps_next, gal_keys_next);
        //////////////////////////////////////
    vector<Modulus> coeff_modulus_last = coeff_modulus;
    coeff_modulus_last.erase(coeff_modulus_last.begin() + 2, coeff_modulus_last.end()-1);
    EncryptionParameters parms_last = parms;
    parms_last.set_coeff_modulus(coeff_modulus_last);
    SEALContext context_last = SEALContext(parms_last, true, sec_level_type::none);

    SecretKey sk_last;
    sk_last.data().resize(coeff_modulus_last.size() * degree);
    sk_last.parms_id() = context_last.key_parms_id();
    util::set_poly(secret_key.data().data(), degree, coeff_modulus_last.size() - 1, sk_last.data().data());
    util::set_poly(
        secret_key.data().data() + degree * (coeff_modulus.size() - 1), degree, 1,
        sk_last.data().data() + degree * (coeff_modulus_last.size() - 1));
    KeyGenerator keygen_last(context_last, sk_last); 
    keygen_last.create_galois_keys(steps, gal_keys_last);
    PublicKey public_key_last;
    keygen_last.create_public_key(public_key_last);
    
    //////////////////////////////////////

    vector<vector<Ciphertext>> packedSICfromPhase1(numcores,vector<Ciphertext>(numOfTransactions/numcores/poly_modulus_degree)); // Assume numOfTransactions/numcores/poly_modulus_degree is integer, pad if needed

    NTL::SetNumThreads(numcores);
    SecretKey secret_key_blank;

    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;
    time_start = chrono::high_resolution_clock::now();

    MemoryPoolHandle my_pool = MemoryPoolHandle::New();
    auto old_prof = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool)));
    NTL_EXEC_RANGE(numcores, first, last);
    for(int i = first; i < last; i++){
        counter[i] = numOfTransactions/numcores*i;
        
        size_t j = 0;
        while(j < numOfTransactions/numcores/poly_modulus_degree){
            if(!i)
                cout << "Phase 1, Core " << i << ", Batch " << j << endl;
            loadClues(SICPVW_multicore[i], counter[i], counter[i]+poly_modulus_degree, params);
            packedSICfromPhase1[i][j] = serverOperations1obtainPackedSIC(SICPVW_multicore[i], switchingKey, relin_keys, gal_keys,
                                                            poly_modulus_degree, context, params, poly_modulus_degree);
            j++;
            counter[i] += poly_modulus_degree;
            SICPVW_multicore[i].clear();
        }
        
    }
    NTL_EXEC_RANGE_END;
    MemoryManager::SwitchProfile(std::move(old_prof));


    // step 4. detector operations
    vector<vector<vector<Ciphertext>>> lhs_multi(numcores);
    vector<vector<Ciphertext>> lhs_multi_ctr(numcores);
    vector<Ciphertext> rhs_multi(numcores);
    vector<vector<vector<int>>> bipartite_map(numcores);

    bipartiteGraphWeightsGeneration(bipartite_map_glb, weights_glb, numOfTransactions,OMRtwoM,repeatition_glb,seed_glb);


    NTL_EXEC_RANGE(numcores, first, last);
    for(int i = first; i < last; i++){
        MemoryPoolHandle my_pool = MemoryPoolHandle::New();
        auto old_prof = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool)));
        size_t j = 0;
        counter[i] = numOfTransactions/numcores*i;

        while(j < numOfTransactions/numcores/poly_modulus_degree){
            if(!i)
                cout << "Phase 2-3, Core " << i << ", Batch " << j << endl;
            loadData(payload_multicore[i], counter[i], counter[i]+poly_modulus_degree);
            vector<vector<Ciphertext>> templhs;
            vector<Ciphertext> templhsctr;
            Ciphertext temprhs;
            serverOperations3therest(templhs, templhsctr, bipartite_map[i], temprhs,
                            packedSICfromPhase1[i][j], payload_multicore[i], relin_keys, gal_keys_next, public_key_last,
                            poly_modulus_degree, context_next, context_last, params, poly_modulus_degree, counter[i]);
            if(j == 0){
                lhs_multi[i] = templhs;
                lhs_multi_ctr[i] = templhsctr;
                rhs_multi[i] = temprhs;
            } else {
                for(size_t q = 0; q < lhs_multi[i].size(); q++){
                    for(size_t w = 0; w < lhs_multi[i][q].size(); w++){
                        evaluator.add_inplace(lhs_multi[i][q][w], templhs[q][w]);
                    }
                }
                for(size_t q = 0; q < lhs_multi_ctr[i].size(); q++){
                    evaluator.add_inplace(lhs_multi_ctr[i][q], templhsctr[q]);
                }
                evaluator.add_inplace(rhs_multi[i], temprhs);
            }
            j++;
            payload_multicore[i].clear();
        }
        
        MemoryManager::SwitchProfile(std::move(old_prof));
    }
    NTL_EXEC_RANGE_END;

    for(int i = 1; i < numcores; i++){
        for(size_t q = 0; q < lhs_multi[i].size(); q++){
            for(size_t w = 0; w < lhs_multi[i][q].size(); w++){
                evaluator.add_inplace(lhs_multi[0][q][w], lhs_multi[i][q][w]);
            }
        }
        for(size_t q = 0; q < lhs_multi_ctr[i].size(); q++){
            evaluator.add_inplace(lhs_multi_ctr[0][q], lhs_multi_ctr[i][q]);
        }
        evaluator.add_inplace(rhs_multi[0], rhs_multi[i]);
    }

    while(context.last_parms_id() != lhs_multi[0][0][0].parms_id()){
            for(size_t q = 0; q < lhs_multi[0].size(); q++){
                for(size_t w = 0; w < lhs_multi[0][q].size(); w++){
                    evaluator.mod_switch_to_next_inplace(lhs_multi[0][q][w]);
                }
            }
            for(size_t q = 0; q < lhs_multi_ctr[0].size(); q++){
                evaluator.mod_switch_to_next_inplace(lhs_multi_ctr[0][q]);
            }
            evaluator.mod_switch_to_next_inplace(rhs_multi[0]);
        }

    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "\nDetector runnimg time: " << time_diff.count() << "us." << "\n";

    stringstream data_streamdg, data_streamdg2;
    auto digsize = rhs_multi[0].save(data_streamdg);
    for(size_t q = 0; q < lhs_multi[0].size(); q++){
        for(size_t w = 0; w < lhs_multi[0][q].size(); w++){
            digsize += lhs_multi[0][q][w].save(data_streamdg2);
        }
    }
    for(size_t q = 0; q < lhs_multi_ctr[0].size(); q++){
        digsize += lhs_multi_ctr[0][q].save(data_streamdg2);
    }
    cout << "Digest size: " << digsize << " bytes" << endl;

    // step 5. receiver decoding
    bipartiteGraphWeightsGeneration(bipartite_map_glb, weights_glb, numOfTransactions,OMRtwoM,repeatition_glb,seed_glb);
    time_start = chrono::high_resolution_clock::now();
    auto res = receiverDecodingOMR3(lhs_multi[0], lhs_multi_ctr[0], bipartite_map[0], rhs_multi[0],
                        poly_modulus_degree, secret_key, context, numOfTransactions);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "\nRecipient runnimg time: " << time_diff.count() << "us." << "\n";

    if(checkRes(expected, res))
        cout << "Result is correct!" << endl;
    else
        cout << "Overflow" << endl;
    
    for(size_t i = 0; i < res.size(); i++){

    }
    
}


int main(){

    cout << "+------------------------------------+" << endl;
    cout << "| Demos                              |" << endl;
    cout << "+------------------------------------+" << endl;
    cout << "| 1. OMD1p Detection Key Size        |" << endl;
    cout << "| 2. OMR1p/OMR2p Detection Key Size  |" << endl;
    cout << "| 3. OMD1p                           |" << endl;
    cout << "| 4. OMR1p Single Thread             |" << endl;
    cout << "| 5. OMR2p Single Thread             |" << endl;
    cout << "| 6. OMR1p Two Threads               |" << endl;
    cout << "| 7. OMR2p Two Threads               |" << endl;
    cout << "| 8. OMR1p Four Threads              |" << endl;
    cout << "| 9. OMR2p Four Threads              |" << endl;
    cout << "+------------------------------------+" << endl;

    int selection = 0;
    bool valid = true;
    do
    {
        cout << endl << "> Run demos (1 ~ 9) or exit (0): ";
        if (!(cin >> selection))
        {
            valid = false;
        }
        else if (selection < 0 || selection > 9)
        {
            valid = false;
        }
        else
        {
            valid = true;
        }
        if (!valid)
        {
            cout << "  [Beep~~] valid option: type 0 ~ 9" << endl;
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
        }
    } while (!valid);

    switch (selection)
        {
        case 1:
            OMDlevelspecificDetectKeySize();
            break;

        case 2:
            levelspecificDetectKeySize();
            break;

        case 3:
            numcores = 1;
            OMD1p();
            break;

        case 4:
            numcores = 1;
            OMR2();
            break;

        case 5:
            numcores = 1;
            OMR3();
            break;
        
        case 6:
            numcores = 2;
            OMR2();
            break;

        case 7:
            numcores = 2;
            OMR3();
            break;
        
        case 8:
            numcores = 4;
            OMR2();
            break;

        case 9:
            numcores = 4;
            OMR3();
            break;

        case 0:
            return 0;
        }
    
    
}