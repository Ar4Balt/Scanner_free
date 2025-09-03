# 🔍 Stealth Network Scanner

Многопоточный сканер портов на **C++17** с поддержкой:

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

### Linux / macOS

```bash
sudo apt install g++ cmake make -y   # (Linux)
brew install cmake                   # (macOS)
````

### Сборка

```bash
mkdir build && cd build
cmake ..
make
```

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

| Опция          | Описание                              |
| -------------- | ------------------------------------- |
| `-t <target>`  | IP или hostname цели                  |
| `-p <ports>`   | Диапазон/список портов                |
| `-m <threads>` | Количество потоков (по умолчанию 100) |
| `-o <file>`    | Сохранить результат в JSON            |
| `--syn`        | Включить SYN-сканирование (Linux)     |
| `--banner`     | Включить Banner Grabbing              |
| `--timeout`    | Таймаут (мс)                          |

---

## 📂 Структура проекта

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