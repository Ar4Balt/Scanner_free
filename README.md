# 🔍 Stealth Network Scanner

Многопоточный сканер портов на **C++17** с поддержкой TCP Connect Scan, SYN-сканирования (требует root), Banner Grabbing и сохранением результатов в **JSON**.

<[image]("images/ChatGPT Image 1 сент. 2025 г., 23_02_06.png")>

---

## ✨ Возможности

- 🚀 **Высокая скорость** — многопоточность (std::thread + очередь задач).  
- 🕵️ **Stealth-режим** — SYN-сканирование через сырые сокеты.  
- 📡 **Banner Grabbing** — извлечение баннеров сервисов.  
- 📂 **JSON-вывод** — результаты сохраняются в структурированном виде.  
- 🎯 **Гибкость** — поддержка диапазонов портов (`1-1000`) и одиночных значений.  

---

## ⚙️ Установка

### Вариант 1. Ручная компиляция

#### Установить зависимости
```bash
sudo apt update
sudo apt install g++ make cmake nlohmann-json3-dev -y
````

#### Скомпилировать

```bash
g++ -o scanner scanner.cpp -pthread -std=c++17
```

---

### Вариант 2. Сборка через CMake

1. Создай файл `CMakeLists.txt` в корне проекта:

```cmake
cmake_minimum_required(VERSION 3.10)
project(StealthScanner)

set(CMAKE_CXX_STANDARD 17)

find_package(nlohmann_json 3.2.0 REQUIRED)

add_executable(scanner scanner.cpp)
target_link_libraries(scanner PRIVATE nlohmann_json::nlohmann_json pthread)
```

2. Выполни сборку:

```bash
mkdir build && cd build
cmake ..
make
```

3. Запусти:

```bash
./scanner -t 192.168.1.1 -p 1-100 -m 50 -o results.json
```

---

## 🚀 Примеры использования

### TCP Connect Scan (по умолчанию)

```bash
./scanner -t 192.168.1.1 -p 1-100 -m 50 -o results.json
```

Сканирует порты **1-100** с 50 потоками и сохраняет результат в `results.json`.

---

### SYN-сканирование (нужны права root)

```bash
sudo ./scanner -t 192.168.1.1 -p 1-100 -s
```

Выполняет stealth-сканирование (отправка SYN-пакетов без полного рукопожатия).

---

### Banner Grabbing

```bash
./scanner -t 192.168.1.1 -p 22-25,80,443 -b
```

Извлекает баннеры сервисов (например, SSH, HTTP, SMTP).

---

## 📊 Формат JSON-вывода

Пример `results.json`:

```json
{
    "target": "192.168.1.1",
    "open_ports": [22, 80, 443],
    "timestamp": 1735928475123456
}
```

---

## 🔑 Опции запуска

| Опция          | Описание                              |
| -------------- | ------------------------------------- |
| `-t <target>`  | IP или hostname цели                  |
| `-p <ports>`   | Диапазон портов (например, `1-1000`)  |
| `-m <threads>` | Количество потоков                    |
| `-o <file>`    | Сохранить результат в JSON            |
| `-s`           | Включить SYN-сканирование (root only) |
| `-b`           | Включить Banner Grabbing              |

---

## ⚠️ Внимание

Используй сканер **только для тестирования своих сетей** или с разрешения владельца.
Автор не несёт ответственности за нелегальное использование.