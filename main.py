def msg_and_key():
    msg = input("Сообщение: ").upper()
    key = input("Ключ: ").upper()
    key_map = ""
    j = 0
    for i in range(len(msg)):
        if ord(msg[i]) == 32:
            key_map += " "
        else:
            if j < len(key):
                key_map += key[j]
                j += 1
            else:
                j = 0
                key_map += key[j]
                j += 1
    return msg, key_map

def create_vigenere_table():
    table = []
    for i in range(32):
        table.append([])

    for row in range(32):
        for column in range(32):
            if (row + ord('А')) + column > ord('Я'):
                table[row].append(chr((row + ord('А')) + column - 32))
            else:
                table[row].append(chr((row + ord('А')) + column))
    return table

def cipher_encryption(message, mapped_key):
    table = create_vigenere_table()
    encrypted_text = ""
    for i in range(len(message)):
        if message[i] == chr(32):
            encrypted_text += " "
        else:
            row = ord(message[i]) - ord('А')
            column = ord(mapped_key[i]) - ord('А') +1
            encrypted_text += table[row][column]

    print("Зашифрованное сообщение: {}".format(encrypted_text))

def itr_count(mapped_key, message):
    counter = 0
    result = ""
    for i in range(32):
        if mapped_key + i > ord('Я'):
            result += chr(mapped_key + (i - 32))
        else:
            result += chr(mapped_key + i)
    for i in range(len(result)):
        if result[i] == chr(message):
            break
        else:
            counter += 1
    return counter

def cipher_decryption(message, mapped_key):
    table = create_vigenere_table()
    decrypted_text = ""

    for i in range(len(message)):
        if message[i] == chr(32):
            decrypted_text += " "
        else:
            decrypted_text += chr(ord('А') -1 + itr_count(ord(mapped_key[i]), ord(message[i])))

    print("Расшифрованное сообщение: {}".format(decrypted_text))

def main():
    print("Ключ и Сообщение только на русском, алфавитными буквами")
    choice = int(input("1. Зашифрование\n2. Расшифрование\nВыбери (1,2): "))
    if choice == 1:
        print("---Зашифрование---")
        message, mapped_key = msg_and_key()
        cipher_encryption(message, mapped_key)
    elif choice == 2:
        print("---Расшифрование---")
        message, mapped_key = msg_and_key()
        cipher_decryption(message, mapped_key)
    else:
        print("Неверный выбор")

if __name__ == "__main__":
    main()
