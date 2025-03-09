#include <fstream>
#include <string>
#include <iostream>

int main() {
    // Создаем строку из 50 символов
    std::string data(50, 'A');  // Заполнение символами 'A'
    
    // Открываем файл в бинарном режиме
    std::ofstream outFile("data.bin", std::ios::binary);
    
    if (!outFile.is_open()) {
        std::cerr << "Ошибка при открытии файла" << std::endl;
        return 1;
    }
    
    // Записываем данные в файл
    outFile.write(data.c_str(), data.size());
    
    // Закрываем файл
    outFile.close();
    
    if (outFile.good()) {
        std::cout << "Строка успешно записана в файл" << std::endl;
    } else {
        std::cerr << "Ошибка при записи в файл" << std::endl;
        return 1;
    }
    
    return 0;
}