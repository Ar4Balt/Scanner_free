# 🔍 Stealth Network Scanner

Многопоточный сканер портов на **C++17** с поддержкой TCP Connect Scan, упрощённого SYN-сканирования (Linux-only), Banner Grabbing и сохранением результатов в **JSON**.

## ✨ Возможности
- 🚀 **Высокая скорость** — многопоточность (std::thread + очередь задач).  
- 🕵️ **Stealth-режим** — SYN-сканирование через сырые сокеты (Linux).  
- 📡 **Banner Grabbing** — извлечение баннеров сервисов.  
- 📂 **JSON-вывод** — без сторонних библиотек (собственная реализация).  
- 🎯 **Гибкость** — поддержка диапазонов портов (`1-1000`), одиночных (`22,80,443`) и комбинированных.  

<img src="images/ChatGPT Image 1 сент. 2025 г., 23_02_06.png" width="1200"/> 

---

## ✨ Что нового

- 🔄 **Проект структурирован**: код разделён на отдельные модули (utils, scanner, banner, synscan).  
- 🖥 **Кроссплатформенность**:  
  - macOS → работает TCP Connect Scan.  
  - Linux → работает и Connect Scan, и SYN Scan.  
- 🧾 **JSON Writer без зависимостей** — теперь не нужен `nlohmann/json`.  
- 📦 **Поддержка CMake** — сборка одной командой.  
- 🛠 **Удобство расширения** — каждый модуль в своём файле.  

---

## ⚙️ Установка

### Зависимости

**Linux (Ubuntu/Debian):**
```bash
sudo apt update
sudo apt install g++ cmake make -y
````

**macOS (через Homebrew):**

```bash
brew install cmake
```

---

### Сборка

**Linux (Ubuntu/Debuan):**
```bash
mkdir build && cd build
cmake ..
cmake --build .
```

**macOS:**
```bash
cmake -S . -B build && cmake --build build
```

После сборки бинарник будет доступен как `./scanner`.

---

### Запуск

```bash
./scanner -t 192.168.1.1 -p 1-100 -m 50 -o results.json
```

---

## 🚀 Примеры использования

### TCP Connect Scan (по умолчанию)

```bash
./scanner -t 192.168.1.1 -p 1-100 -m 50 -o results.json
```

### SYN-сканирование (Linux, root)

```bash
sudo ./scanner -t 192.168.1.1 -p 1-100 --syn
```

### Banner Grabbing

```bash
./scanner -t 192.168.1.1 -p 22,80,443 --banner
```

---

## 📊 Пример JSON-вывода

```json
{
  "target": "192.168.1.1",
  "results": [
    {"port": 22, "open": true, "banner": "SSH-2.0-OpenSSH_8.2"},
    {"port": 80, "open": true, "banner": "HTTP/1.0 200 OK"},
    {"port": 443, "open": true}
  ]
}
```

---

## 🔑 Опции запуска

| Опция          | Описание                               |
| -------------- | -------------------------------------- |
| `-t <target>`  | IP или hostname цели                   |
| `-p <ports>`   | Диапазон или список портов (`1-100`)   |
| `-m <threads>` | Количество потоков                     |
| `-o <file>`    | Сохранить результат в JSON             |
| `-s`           | Включить SYN-сканирование (Linux only) |
| `-b`           | Включить Banner Grabbing               |

---

## 📂 Основная структура проекта

```
Scanner/
 ├── include/
 │    ├── utils.hpp        # Утилиты: таймеры, JSON-escape, резолвинг, парсинг портов
 │    ├── banner.hpp       # TCP Connect + Banner grabbing
 │    ├── scanner.hpp      # Класс Scanner (многопоточность, результаты)
 │    └── synscan.hpp      # SYN-скан (Linux only)
 ├── src/
 │    ├── main.cpp         # CLI, парсинг аргументов
 │    ├── utils.cpp        # Реализация утилит
 │    ├── banner.cpp       # Реализация banner grabbing
 │    ├── scanner.cpp      # Логика сканера
 │    └── synscan.cpp      # Реализация SYN-скана (Linux)
 ├── CMakeLists.txt
 └── README.md
```

---

## ⚠️ Внимание

Используй сканер **только для тестирования своих сетей** или с разрешения владельца.
Автор не несёт ответственности за нелегальное использование.