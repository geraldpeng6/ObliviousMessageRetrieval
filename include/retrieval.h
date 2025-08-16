#pragma once

#include <algorithm>

/**
 * 确定性索引检索 - Deterministic index retrieval
 * 一个交易占用一位 - One transaction taking one bit
 * @param indexIndicator 索引指示器 - Index indicator
 * @param SIC SIC密文向量 - SIC ciphertext vector
 * @param context SEAL上下文 - SEAL context
 * @param degree 多项式度数 - Polynomial degree
 * @param start 起始位置 - Start position
 * @param isMulti 是否多重 - Whether multi
 */
void deterministicIndexRetrieval(Ciphertext& indexIndicator, const vector<Ciphertext>& SIC, const SEALContext& context,
                                    const size_t& degree, const size_t& start
                                    , bool isMulti = false){
    BatchEncoder batch_encoder(context);                // 批编码器 - Batch encoder
    Evaluator evaluator(context);                       // 求值器 - Evaluator
    vector<uint64_t> pod_matrix(degree, 0ULL);          // POD矩阵 - POD matrix
    // 检查边界条件 - Check boundary conditions
    if(start + SIC.size() > 16*degree){
        cerr << "counter + SIC.size should be less, please check " << start << " " << SIC.size() << endl;
        return;
    }

    // 遍历所有SIC - Iterate through all SIC
    for(size_t i = 0; i < SIC.size(); i++){
        size_t idx = (i+start)/16;                      // 计算索引 - Calculate index
        size_t shift = (i+start) % 16;                  // 计算位移 - Calculate shift
        pod_matrix[idx] = (1<<shift);                   // 设置位 - Set bit
        Plaintext plain_matrix;                         // 明文矩阵 - Plaintext matrix
        batch_encoder.encode(pod_matrix, plain_matrix); // 编码矩阵 - Encode matrix
        evaluator.transform_to_ntt_inplace(plain_matrix, SIC[i].parms_id()); // 转换为NTT形式 - Transform to NTT form
        if(i == 0 && (start%degree) == 0){             // 第一个元素 - First element
            evaluator.multiply_plain(SIC[i], plain_matrix, indexIndicator);
        }
        else{                                           // 其他元素 - Other elements
            Ciphertext temp;                            // 临时密文 - Temporary ciphertext
            evaluator.multiply_plain(SIC[i], plain_matrix, temp);
            evaluator.add_inplace(indexIndicator, temp); // 累加 - Accumulate
        }
        pod_matrix[idx] = 0ULL;                         // 重置位 - Reset bit
    }
}

/**
 * 随机化索引检索 - For randomized index retrieval
 * 我们首先有2个密文，因为我们需要表示N ~= 500,000，所以sqrt(N) < 65537
 * We first have 2 ciphertexts, as we need to represent N ~= 500,000, so sqrt(N) < 65537
 * 我们还需要一个计数器 - We also need a counter
 * 每个消息随机分配到一个槽位 - Each msg is randomly assigned to one slot
 * 然后我们重复这个过程C次并收集部分信息以降低失败概率
 * Then we repeat this process C times and gather partial information to reduce failure probability
 * @param indexIndicator 索引指示器向量 - Index indicator vector
 * @param indexCounters 索引计数器 - Index counters
 * @param SIC SIC密文向量 - SIC ciphertext vector
 * @param context SEAL上下文 - SEAL context
 * @param BFVpk BFV公钥 - BFV public key
 * @param counter 计数器 - Counter
 * @param degree 多项式度数 - Polynomial degree
 * @param C 重复次数 - Number of repetitions
 */
void randomizedIndexRetrieval(vector<vector<Ciphertext>>& indexIndicator, vector<Ciphertext>& indexCounters, vector<Ciphertext>& SIC, const SEALContext& context,
                                        const PublicKey& BFVpk, int counter, const size_t& degree, size_t C){
    BatchEncoder batch_encoder(context);                // 批编码器 - Batch encoder
    Evaluator evaluator(context);                       // 求值器 - Evaluator
    Encryptor encryptor(context, BFVpk);                // 加密器 - Encryptor
    vector<uint64_t> pod_matrix(degree, 0ULL);          // POD矩阵 - POD matrix
    srand(time(NULL));                                  // 设置随机种子 - Set random seed

    if((counter%degree) == 0){ // first msg
        indexIndicator.resize(C);
        indexCounters.resize(C);
        for(size_t i = 0; i < C; i++){
            indexIndicator[i].resize(2); // 2 cts allow 65537^2 total messages, which is in general enough so we hard code this.
            encryptor.encrypt_zero(indexIndicator[i][0]);
            encryptor.encrypt_zero(indexIndicator[i][1]);
            encryptor.encrypt_zero(indexCounters[i]);
            evaluator.transform_to_ntt_inplace(indexIndicator[i][0]);
            evaluator.transform_to_ntt_inplace(indexIndicator[i][1]);
            evaluator.transform_to_ntt_inplace(indexCounters[i]);
        }
    }

    for(size_t i = 0; i < SIC.size(); i++){
        for(size_t j = 0; j < C; j++){
            size_t index = rand()%degree;

            vector<uint64_t> pod_matrix(degree, 0ULL);
            Ciphertext temp;

            pod_matrix[index] = counter/65537;
            if(pod_matrix[index] == 0){
                // then nothing to do
            } else {
                Plaintext plain_matrix;
                batch_encoder.encode(pod_matrix, plain_matrix);
                evaluator.transform_to_ntt_inplace(plain_matrix, SIC[i].parms_id());
                evaluator.multiply_plain(SIC[i], plain_matrix, temp);
                evaluator.add_inplace(indexIndicator[j][0], temp);
            }

            pod_matrix[index] = counter%65537;
            if(pod_matrix[index] == 0){
                // then nothing to do
            } else {
                Plaintext plain_matrix;
                batch_encoder.encode(pod_matrix, plain_matrix);
                evaluator.transform_to_ntt_inplace(plain_matrix, SIC[i].parms_id());
                evaluator.multiply_plain(SIC[i], plain_matrix, temp);
                evaluator.add_inplace(indexIndicator[j][1], temp);
            }

            pod_matrix[index] = 1;
            if(pod_matrix[index] == 0){
                // then nothing to do
            } else {
                Plaintext plain_matrix;
                batch_encoder.encode(pod_matrix, plain_matrix);
                evaluator.transform_to_ntt_inplace(plain_matrix, SIC[i].parms_id());
                evaluator.multiply_plain(SIC[i], plain_matrix, temp);
                evaluator.add_inplace(indexCounters[j], temp);
            }
        }
        counter += 1;
    }
    return;
}

// generate the random assignment of each message represented as a bipartite grap
// generate weights for each assignment
void bipartiteGraphWeightsGeneration(vector<vector<int>>& bipartite_map, vector<vector<int>>& weights, const int& num_of_transactions, const int& num_of_buckets, const int& repetition, const int& seed){
    srand(seed);
    bipartite_map.clear();
    weights.clear();
    bipartite_map.resize(num_of_transactions);
    weights.resize(num_of_transactions);
    for(int i = 0; i < num_of_transactions; i++)
    {
        bipartite_map[i].resize(repetition, -1);
        weights[i].resize(repetition, -1);
        for(int j = 0; j < repetition; j++){
            int temp = rand()%num_of_buckets;
            // avoid repeatition
            while(find(bipartite_map[i].begin(), bipartite_map[i].end(), temp) != bipartite_map[i].end()){
                temp = rand()%num_of_buckets;
            }
            bipartite_map[i][j] = temp;
            // weight is non-zero
            weights[i][j] = rand()%65536 + 1;
        }
    }
}

// Note that real payload size = payloadSize / 2
// Note that we use plaintext to do the multiplication which is very fast
// We the first some number of slots as zero
// Note that if we don't know k
// We can still perform this process
// This is because we know one ciphertext has at most 100 combinations
// (actually it's 107 for 612 bytes, but let's assume 100 for simplicity)
// Say if some msg is randomly assigned to position 55
// If after we know k, we need 300 combinations
// we can just randomly assign that message to 55, 155, or 255
// This is the same as randomly chosen from the 300 combinations
// We will always have 100*integer combinations, 
// because it optimizes the efficiency and reduces the failure probability
// as any number from 1 to 100 slots use only one ciphertext
void payloadRetrievalOptimizedwithWeights(vector<vector<Ciphertext>>& results, const vector<vector<uint64_t>>& payloads, const vector<vector<int>>& bipartite_map, vector<vector<int>>& weights,
                        const vector<Ciphertext>& SIC, const SEALContext& context, const size_t& degree = 32768, const size_t& start = 0, const size_t& local_start = 0, const int payloadSize = 306){ // TODOmulti: can be multithreaded extremely easily
    Evaluator evaluator(context);
    BatchEncoder batch_encoder(context);
    results.resize(SIC.size());

    for(size_t i = 0; i < SIC.size(); i++){
        results[i].resize(1);
        vector<uint64_t> padded(degree, 0);
        for(size_t j = 0; j < bipartite_map[i+start].size(); j++){
            auto paddedStart = bipartite_map[i+start][j]*payloadSize;
            for(size_t k = 0; k < payloads[i+local_start].size(); k++){
                auto toAdd = payloads[i+local_start][k] *weights[i+start][j];
                toAdd %= 65537;
                padded[k+paddedStart] += toAdd;
            }
        }
        Plaintext plain_matrix;
        batch_encoder.encode(padded, plain_matrix);
        evaluator.transform_to_ntt_inplace(plain_matrix, SIC[i].parms_id());

        evaluator.multiply_plain(SIC[i], plain_matrix, results[i][0]);  
    }
}

// use only addition to pack
void payloadPackingOptimized(Ciphertext& result, const vector<vector<Ciphertext>>& payloads, const vector<vector<int>>& bipartite_map, const size_t& degree, 
                        const SEALContext& context, const GaloisKeys& gal_keys, const size_t& start = 0, const int payloadSize = 306){
    Evaluator evaluator(context);

    for(size_t i = 0; i < payloads.size(); i++){
        for(size_t j = 0; j < payloads[i].size(); j++){
            if(i == 0 && j == 0 && (start%degree) == 0)
                result = payloads[i][j];
            else{
                for(size_t k = 0; k < 1; k++){ 
                    evaluator.add_inplace(result, payloads[i][j]); 
                }
            }
        }
    }
}