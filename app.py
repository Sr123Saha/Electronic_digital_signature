import tkinter as tk
from tkinter import messagebox, simpledialog, filedialog
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

def create_signature():
    # Получение данных для подписи от пользователя
    data = simpledialog.askstring("Создание ЭЦП", "Введите данные для подписи:")
    if data:
        # Генерация ключей RSA
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()

        # Создание хеша данных
        hash_data = SHA256.new(data.encode('utf-8'))

        # Создание подписи
        signature = pkcs1_15.new(key).sign(hash_data)

        # Сохранение ключей и подписи в текстовый файл
        filename = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if filename:
            with open(filename, 'w') as f:
                f.write("Приватный ключ:\n")
                f.write(private_key.decode('utf-8'))
                f.write("\n\nПубличный ключ:\n")
                f.write(public_key.decode('utf-8'))
                f.write("\n\nЭЦП:\n")
                f.write(signature.hex())

        messagebox.showinfo("ЭЦП создана", "Ключи и подпись сохранены в файл.")

def verify_signature():
    # Получение данных и подписи от пользователя
    data = simpledialog.askstring("Проверка ЭЦП", "Введите исходные данные:")
    if data:
        signature_hex = simpledialog.askstring("Проверка ЭЦП", "Введите ЭЦП для проверки:")
        if signature_hex:
            # Получение публичного ключа от пользователя
            public_key = simpledialog.askstring("Проверка ЭЦП", "Введите публичный ключ:")
            if public_key:
                # Преобразование подписи из строки в байты
                signature = bytes.fromhex(signature_hex)

                # Создание хеша данных
                hash_data = SHA256.new(data.encode('utf-8'))

                # Проверка подписи
                try:
                    pkcs1_15.new(RSA.import_key(public_key)).verify(hash_data, signature)
                    messagebox.showinfo("Результат проверки", "ЭЦП верна.")
                except (ValueError, TypeError):
                    messagebox.showerror("Ошибка", "Недействительная подпись или ключ.")

def main():
    # Создание главного окна приложения
    root = tk.Tk()
    root.title("Приложение для создания ЭЦП")

    # Создание кнопки для создания ЭЦП
    button_sign = tk.Button(root, text="Создать ЭЦП", command=create_signature)
    button_sign.pack(pady=10)
    
    button_verify = tk.Button(root, text="Проверить ЭЦП", command=verify_signature)
    button_verify.pack(pady=10)

    # Запуск основного цикла приложения
    root.mainloop()

if __name__ == "__main__":
    main()