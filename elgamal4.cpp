#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <chrono>

// Размер блока (в байтах)
const size_t BLOCK_SIZE = 32; // 256 бит для secp256k1

// Функция для чтения бинарного файла по блокам
std::vector<std::vector<unsigned char>> readFileByBlocks(const std::string& filename, size_t blockSize) {
    std::ifstream file(filename, std::ios::binary);
    std::vector<std::vector<unsigned char>> blocks;
    std::vector<unsigned char> buffer(blockSize);

    while (file.read(reinterpret_cast<char*>(buffer.data()), blockSize)) {
        blocks.push_back(buffer);
    }

    // Обработка последнего блока, если его размер меньше BLOCK_SIZE
    if (file.gcount() > 0) {
        buffer.resize(file.gcount());
        blocks.push_back(buffer);
    }

    return blocks;
}

// Функция для записи бинарного файла
void writeFile(const std::string& filename, const std::vector<std::vector<unsigned char>>& data) {
    std::ofstream file(filename, std::ios::binary);
    for (const auto& block : data) {
        file.write(reinterpret_cast<const char*>(block.data()), block.size());
    }
}

// Функция для шифрования блока
std::vector<unsigned char> encryptBlock(const std::vector<unsigned char>& plaintext, EC_KEY* key) {
    std::vector<unsigned char> ciphertext;

    const EC_GROUP* group = EC_KEY_get0_group(key);
    const EC_POINT* pub_key = EC_KEY_get0_public_key(key);

    // Генерация случайного числа k
    BIGNUM* k = BN_new();
    BN_rand_range(k, EC_GROUP_get0_order(group));

    // Вычисление точек C1 = k*G и C2 = M + k*PubKey
    EC_POINT* C1 = EC_POINT_new(group);
    EC_POINT_mul(group, C1, k, nullptr, nullptr, nullptr);

    EC_POINT* temp = EC_POINT_new(group);
    EC_POINT_mul(group, temp, nullptr, pub_key, k, nullptr);

    // Преобразование открытого текста в точку на кривой
    EC_POINT* M = EC_POINT_new(group);
    EC_POINT_oct2point(group, M, plaintext.data(), plaintext.size(), nullptr);

    EC_POINT* C2 = EC_POINT_new(group);
    EC_POINT_add(group, C2, M, temp, nullptr);

    // Сериализация точек C1 и C2
    size_t len = EC_POINT_point2oct(group, C1, POINT_CONVERSION_COMPRESSED, nullptr, 0, nullptr);
    std::vector<unsigned char> C1_serialized(len);
    EC_POINT_point2oct(group, C1, POINT_CONVERSION_COMPRESSED, C1_serialized.data(), len, nullptr);

    len = EC_POINT_point2oct(group, C2, POINT_CONVERSION_COMPRESSED, nullptr, 0, nullptr);
    std::vector<unsigned char> C2_serialized(len);
    EC_POINT_point2oct(group, C2, POINT_CONVERSION_COMPRESSED, C2_serialized.data(), len, nullptr);

    // Объединение C1 и C2 в один шифротекст
    ciphertext.insert(ciphertext.end(), C1_serialized.begin(), C1_serialized.end());
    ciphertext.insert(ciphertext.end(), C2_serialized.begin(), C2_serialized.end());

    // Очистка
    BN_free(k);
    EC_POINT_free(C1);
    EC_POINT_free(C2);
    EC_POINT_free(M);
    EC_POINT_free(temp);

    return ciphertext;
}

// Функция для дешифрования блока
std::vector<unsigned char> decryptBlock(const std::vector<unsigned char>& ciphertext, EC_KEY* key) {
    std::vector<unsigned char> plaintext;

    const EC_GROUP* group = EC_KEY_get0_group(key);
    const BIGNUM* priv_key = EC_KEY_get0_private_key(key);

    // Разделение шифротекста на C1 и C2
    size_t point_len = (EC_GROUP_get_degree(group) + 7) / 8;
    std::vector<unsigned char> C1_serialized(ciphertext.begin(), ciphertext.begin() + point_len);
    std::vector<unsigned char> C2_serialized(ciphertext.begin() + point_len, ciphertext.end());

    // Десериализация точек C1 и C2
    EC_POINT* C1 = EC_POINT_new(group);
    EC_POINT_oct2point(group, C1, C1_serialized.data(), C1_serialized.size(), nullptr);

    EC_POINT* C2 = EC_POINT_new(group);
    EC_POINT_oct2point(group, C2, C2_serialized.data(), C2_serialized.size(), nullptr);

    // Вычисление M = C2 - priv_key * C1
    EC_POINT* M = EC_POINT_new(group);
    EC_POINT_mul(group, M, nullptr, C1, priv_key, nullptr);
    EC_POINT_invert(group, M, nullptr);
    EC_POINT_add(group, M, C2, M, nullptr);

    // Сериализация точки M в открытый текст
    size_t len = EC_POINT_point2oct(group, M, POINT_CONVERSION_COMPRESSED, nullptr, 0, nullptr);
    plaintext.resize(len);
    EC_POINT_point2oct(group, M, POINT_CONVERSION_COMPRESSED, plaintext.data(), len, nullptr);

    // Очистка
    EC_POINT_free(C1);
    EC_POINT_free(C2);
    EC_POINT_free(M);

    return plaintext;
}

int main() {
    // Инициализация OpenSSL
    OpenSSL_add_all_algorithms();

    // Генерация ключей
    EC_KEY* key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!key) {
        std::cerr << "Failed to create EC key" << std::endl;
        return 1;
    }

    if (!EC_KEY_generate_key(key)) {
        std::cerr << "Failed to generate EC key" << std::endl;
        EC_KEY_free(key);
        return 1;
    }

    // Чтение бинарного файла по блокам
    std::vector<std::vector<unsigned char>> blocks = readFileByBlocks("data.bin", BLOCK_SIZE);

    // Шифрование каждого блока
    std::vector<std::vector<unsigned char>> encryptedBlocks;
    size_t blockCount = 0;
    double totalEncryptionTime = 0.0;

    for (const auto& block : blocks) {
        auto start = std::chrono::high_resolution_clock::now(); // Замер времени начала шифрования

        std::vector<unsigned char> encryptedBlock = encryptBlock(block, key);
        encryptedBlocks.push_back(encryptedBlock);

        auto end = std::chrono::high_resolution_clock::now(); // Замер времени окончания шифрования
        std::chrono::duration<double> elapsed = end - start;
        totalEncryptionTime += elapsed.count();

        std::cout << "Block " << blockCount + 1 << " encrypted in " << elapsed.count() << " seconds." << std::endl;
        blockCount++;
    }

    std::cout << "Total encryption time: " << totalEncryptionTime << " seconds." << std::endl;
    std::cout << "Total blocks: " << blockCount << std::endl;

    // Запись зашифрованного файла
    writeFile("encrypted.bin", encryptedBlocks);

    // Дешифрование каждого блока
    std::vector<std::vector<unsigned char>> decryptedBlocks;
    for (const auto& block : encryptedBlocks) {
        std::vector<unsigned char> decryptedBlock = decryptBlock(block, key);
        decryptedBlocks.push_back(decryptedBlock);
    }

    // Запись дешифрованного файла
    writeFile("decrypted.bin", decryptedBlocks);

    // Очистка
    EC_KEY_free(key);
    EVP_cleanup();

    return 0;
}