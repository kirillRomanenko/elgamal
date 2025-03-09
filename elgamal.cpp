#include <iostream>
#include <fstream>
#include <vector>
#include <stdexcept>
#include <random>
#include <chrono>
#include <sstream> // Добавлено для stringstream
#include <string> // Добавлено для string

#include <NTL/ZZ.h>
#include <NTL/GF2E.h>
#include <NTL/ZZ_pE.h>
#include <NTL/GF2X.h>

using namespace std;
using namespace NTL;

// Структура для хранения параметров эллиптической кривой
struct EllipticCurveParams {
    ZZ p;          // Порядок поля
    ZZ a;          // Параметр a кривой
    ZZ b;          // Параметр b кривой
    ZZ x;          // X координата базовой точки G
    ZZ y;          // Y координата базовой точки G
    ZZ n;          // Порядок базовой точки G
};


// Функция для проверки, является ли точка на эллиптической кривой
bool isOnCurve(const EllipticCurveParams& params, const ZZ& x, const ZZ& y) {
    if (x == ZZ(0) && y == ZZ(0)) return true; // Точка O (бесконечно удаленная)

    ZZ left = (y * y) % params.p;
    ZZ right = ((x * x * x) + (params.a * x) + params.b) % params.p;
    return left == right;
}

// Функция для сложения точек на эллиптической кривой (в аффинных координатах)
pair<ZZ, ZZ> pointAdd(const EllipticCurveParams& params, const pair<ZZ, ZZ>& P, const pair<ZZ, ZZ>& Q) {
    if (P.first == ZZ(0) && P.second == ZZ(0)) return Q; // P = O
    if (Q.first == ZZ(0) && Q.second == ZZ(0)) return P; // Q = O
    if (P.first == Q.first && P.second != Q.second) return {ZZ(0), ZZ(0)}; // P = -Q

    ZZ x3, y3;

    if (P.first == Q.first && P.second == Q.second) {
        // Удвоение точки
        ZZ s = (((ZZ(3) * P.first * P.first) + params.a) * InvMod(ZZ(2) * P.second, params.p)) % params.p;
        x3 = (s * s - ZZ(2) * P.first) % params.p;
        y3 = (s * (P.first - x3) - P.second) % params.p;
    } else {
        // Сложение двух разных точек
        ZZ s = ((Q.second - P.second) * InvMod(Q.first - P.first, params.p)) % params.p;
        x3 = (s * s - P.first - Q.first) % params.p;
        y3 = (s * (P.first - x3) - P.second) % params.p;
    }

    if (x3 < 0) x3 += params.p;
    if (y3 < 0) y3 += params.p;

    return {x3, y3};
}


// Функция для умножения точки на скаляр (метод "умножения и сложения")
pair<ZZ, ZZ> pointScalarMultiply(const EllipticCurveParams& params, const pair<ZZ, ZZ>& P, const ZZ& k) {
    pair<ZZ, ZZ> result = {ZZ(0), ZZ(0)}; // O
    pair<ZZ, ZZ> Q = P;
    ZZ kk = k;

    while (kk > 0) {
        if ((kk % 2) == 1) {
            result = pointAdd(params, result, Q);
        }
        Q = pointAdd(params, Q, Q);
        kk /= 2;
    }
    return result;
}

// Генерация параметров эллиптической кривой (пример)
// В реальных приложениях нужно использовать стандартизированные кривые
EllipticCurveParams generateEllipticCurve() {
    EllipticCurveParams params;

    // Пример: Кривая secp256k1 (для демонстрации - уменьшенные параметры)
    params.p = ZZ(23);  // Простое число (порядок поля)
    params.a = ZZ(1);  // Параметр a
    params.b = ZZ(1);  // Параметр b
    params.x = ZZ(3);  // X координата базовой точки G
    params.y = ZZ(10);  // Y координата базовой точки G
    params.n = ZZ(29);  // Порядок базовой точки G

    // Проверка базовой точки на кривой
    if (!isOnCurve(params, params.x, params.y)) {
        throw runtime_error("Базовая точка G не лежит на кривой!");
    }

    return params;
}


// Генерация открытого и секретного ключей Эль-Гамаля
pair<pair<ZZ, ZZ>, ZZ> generateElGamalKeys(const EllipticCurveParams& params) {
    // Генератор случайных чисел (можно использовать более криптографически безопасный)
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<long> distrib(1, to_long(params.n) - 1); // k < n

    ZZ privateKey = ZZ(distrib(gen));
    pair<ZZ, ZZ> publicKey = pointScalarMultiply(params, {params.x, params.y}, privateKey);

    return {publicKey, privateKey};
}


// Шифрование сообщения с использованием Эль-Гамаля на эллиптической кривой
pair<pair<ZZ, ZZ>, vector<ZZ>> encryptElGamal(const EllipticCurveParams& params, const pair<ZZ, ZZ>& publicKey, const vector<ZZ>& message) {
    // Генератор случайных чисел
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<long> distrib(1, to_long(params.n) - 1); // k < n

    ZZ k = ZZ(distrib(gen)); // Случайное число

    // Вычисление C1
    pair<ZZ, ZZ> C1 = pointScalarMultiply(params, {params.x, params.y}, k);

    // Вычисление C2 (зашифрованное сообщение)
    vector<ZZ> C2;
    for (const ZZ& m : message) {
        pair<ZZ, ZZ> kPubKey = pointScalarMultiply(params, publicKey, k);
        ZZ cipher = (m + kPubKey.first) % params.p; //  m + x_координата(k * pubKey)
        C2.push_back(cipher);
    }

    return {C1, C2};
}


// Расшифрование сообщения с использованием Эль-Гамаля на эллиптической кривой
vector<ZZ> decryptElGamal(const EllipticCurveParams& params, const pair<ZZ, ZZ>& C1, const vector<ZZ>& C2, const ZZ& privateKey) {
    // Вычисление k * privateKey * G
    pair<ZZ, ZZ> kPrivKeyG = pointScalarMultiply(params, C1, privateKey);

    // Расшифровка
    vector<ZZ> message;
    for (const ZZ& cipher : C2) {
        ZZ decrypted = (cipher - kPrivKeyG.first) % params.p;  // cipher - x_координата(k * privateKey * G)
        if (decrypted < 0) decrypted += params.p;
        message.push_back(decrypted);
    }

    return message;
}


// Преобразование бинарных данных в вектор ZZ (для шифрования)
vector<ZZ> binaryToZZVector(const vector<unsigned char>& binaryData, const ZZ& p) {
    vector<ZZ> zzVector;
    for (unsigned char byte : binaryData) {
        zzVector.push_back(ZZ(byte));
    }
    return zzVector;
}

// Преобразование вектора ZZ в бинарные данные (для расшифровки)
vector<unsigned char> zzVectorToBinary(const vector<ZZ>& zzVector) {
    vector<unsigned char> binaryData;
    for (const ZZ& zz : zzVector) {
        binaryData.push_back(static_cast<unsigned char>(to_long(zz)));
    }
    return binaryData;
}

// Функция для чтения бинарного файла
vector<unsigned char> readBinaryFile(const string& filename) {
    ifstream file(filename, ios::binary);
    if (!file) {
        throw runtime_error("Не удалось открыть файл: " + filename);
    }

    vector<unsigned char> data((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
    file.close();
    return data;
}

// Функция для записи бинарного файла
void writeBinaryFile(const string& filename, const vector<unsigned char>& data) {
    ofstream file(filename, ios::binary);
    if (!file) {
        throw runtime_error("Не удалось создать файл: " + filename);
    }
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    file.close();
}

// Функция для записи ZZ в бинарный файл
void writeZZ(ofstream& file, const ZZ& num) {
    stringstream ss;
    ss << num;
    string str = ss.str();
    size_t len = str.size();
    file.write(reinterpret_cast<const char*>(&len), sizeof(len));
    file.write(str.c_str(), len);
}

// Функция для чтения ZZ из бинарного файла
ZZ readZZ(ifstream& file) {
    size_t len;
    file.read(reinterpret_cast<char*>(&len), sizeof(len));
    char* str = new char[len + 1];
    file.read(str, len);
    str[len] = '\0';
    ZZ num;
    stringstream ss(str);
    ss >> num;
    delete[] str;
    return num;
}


int main() {
    try {
        // 1. Генерация параметров эллиптической кривой
        EllipticCurveParams params = generateEllipticCurve();

        // 2. Генерация ключей
        auto keyPair = generateElGamalKeys(params);
        pair<ZZ, ZZ> publicKey = keyPair.first;
        ZZ privateKey = keyPair.second;

        cout << "Параметры эллиптической кривой:" << endl;
        cout << "  p: " << params.p << endl;
        cout << "  a: " << params.a << endl;
        cout << "  b: " << params.b << endl;
        cout << "  G (x): " << params.x << endl;
        cout << "  G (y): " << params.y << endl;
        cout << "  n: " << params.n << endl;
        cout << "Открытый ключ (X,Y): (" << publicKey.first << ", " << publicKey.second << ")" << endl;
        cout << "Секретный ключ: " << privateKey << endl;

        // 3. Чтение бинарного файла
        string inputFile = "data.bin";
        vector<unsigned char> binaryData = readBinaryFile(inputFile);

        // 4. Шифрование
        vector<ZZ> message = binaryToZZVector(binaryData, params.p); // Преобразование в ZZ
        auto ciphertext = encryptElGamal(params, publicKey, message);

        // 5. Запись зашифрованного файла (C1 и C2 в один файл)
        string encryptedFile = "encrypted.bin";
        ofstream outputFile(encryptedFile, ios::binary);
        if (!outputFile) {
             throw runtime_error("Не удалось создать файл: " + encryptedFile);
        }

        // Запись C1 (две ZZ координаты)
        writeZZ(outputFile, ciphertext.first.first); // X координата C1
        writeZZ(outputFile, ciphertext.first.second); // Y координата C1

        // Запись C2 (вектор ZZ, сначала размер вектора)
        size_t c2Size = ciphertext.second.size();
        outputFile.write(reinterpret_cast<const char*>(&c2Size), sizeof(c2Size));  // Размер C2
        for (const ZZ& zz : ciphertext.second) {
            writeZZ(outputFile, zz);
        }

        outputFile.close();
        cout << "Файл зашифрован и сохранен в " << encryptedFile << endl;


        // 6. Расшифрование
        // Чтение зашифрованного файла (C1 и C2)
        ifstream encryptedInputFile(encryptedFile, ios::binary);
        if (!encryptedInputFile) {
            throw runtime_error("Не удалось открыть файл: " + encryptedFile);
        }

        pair<ZZ, ZZ> readC1;
        vector<ZZ> readC2;
        // Чтение C1 (две ZZ координаты)
        readC1.first = readZZ(encryptedInputFile);
        readC1.second = readZZ(encryptedInputFile);

        // Чтение C2
        size_t readC2Size;
        encryptedInputFile.read(reinterpret_cast<char*>(&readC2Size), sizeof(readC2Size));  // Размер C2
        readC2.resize(readC2Size);
        for (size_t i = 0; i < readC2Size; ++i) {
            readC2[i] = readZZ(encryptedInputFile);
        }
        encryptedInputFile.close();


        vector<ZZ> decryptedMessage = decryptElGamal(params, readC1, readC2, privateKey);

        // 7. Преобразование расшифрованного ZZ в бинарные данные
        vector<unsigned char> decryptedBinaryData = zzVectorToBinary(decryptedMessage);

        // 8. Запись расшифрованного файла
        string outputFileDecrypted = "decrypted.bin";
        writeBinaryFile(outputFileDecrypted, decryptedBinaryData);
        cout << "Файл расшифрован и сохранен в " << outputFileDecrypted << endl;

    } catch (const exception& error) {
        cerr << "Ошибка: " << error.what() << endl;
        return 1;
    }

    return 0;
}