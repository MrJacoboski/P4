# Шифровальное приложение на Flask
Данное приложение предоставляет возможность шифровать и дешифровать текст с использованием шифров Цезаря и Вижинера. Пользователи могут добавляться с уникальными секретными ключами, которые используются для доступа к шифровальным методам.

Установка

1. Клонировать репозиторий: git clone https://github.com/MrJacoboski/P4.git
Установить зависимости:
2. Установить зависимости: pip install -r requirements.txt 
3. Запустить приложение: python week_1.py

Использование
1. Добавить пользователя: 
- Отправить POST запрос на /users с данными пользователя.
2. Получить список пользователей: 
- Отправить GET запрос на /users.
3. Выбрать метод шифрования: 
- Перейти на страницу /methods для просмотра доступных методов.
4. Шифровать/дешифровать текст: 
- Перейти на страницу /encrypt и выбрать метод шифрования, пользователя и действие. 
- Ввести текст для шифрования и ключ (для метода Вижинера). 
- Отправить запрос.
5. Просмотреть и удалить сессии: 
- Перейти на страницу /sessions для просмотра всех сессий.
- Для удаления сессии отправить DELETE запрос на /sessions/<session_id> с секретным ключом.

Дополнительная информация
- Приложение использует шифры Цезаря и Вижинера для шифровки текста.
- Информация о пользователях и сессиях хранится в памяти и сбрасывается при перезапуске приложения.
- Можно добавлять новые шифровальные методы, указав их параметры в формате JSON.
- Поддерживается шифровка текста на русском языке.
- Приложение создано с целью демонстрации работы с Flask и шифровальными методами.
