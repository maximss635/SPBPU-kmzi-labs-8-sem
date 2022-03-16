1 лаба:
в victim/

генерим ключи

python rsa_gen_keys.py --path-out-private res/rsa_private.key \
       --path-out-public res/rsa_public.key


python gen_session_key.py --path-out res/data.key

шифруем файл

python encrypt.py --path-in res/test.txt \
       --rsa-key res/rsa_public.key --data-key res/data.key

расшифровываем

python decrypt.py --path-in res/test.txt.crypted --rsa-key \
       res/rsa_private.key

Расшифрованный должен совпасть с исходным

Подписываем файл

python sign.py --path-in res/test.txt --rsa-key res/rsa_private.key

Проверяем подпись

python sign_check.py --path-in res/test.txt --path-sign \
       res/test.txt.sign --rsa-key res/rsa_public.key

Должна быть надпись что подпись верная

****************************************************

2 лаба:
в attacker/

3 атки:                   

python main.py --attack 1

python main.py --attack 2

python main.py --attack 3

и генерация параметров

python main.py --generate [BIT_SIZE напр. 1024]

****************************************************

3 лаба:

атака в attacker/

python main.py --attack 4

и шифрование в victim/
шифруем

python encrypt_oaep.py --path-in res/test.txt --rsa-key res/rsa_public.key \
       --data-key res/data.key

и расшифровываем

python decrypt_oaep.py --path-in res/test.txt.crypted --rsa-key \
       res/rsa_private.key

расшифрованный должен совпасть с исходным

****************************************************

8 лаба:

EllipticAlgs/

python main.py --number *СОСТАВНОЕ ЧИСЛО* --base *РАЗМЕР БАЗЫ*

например
python main.py --number 9679022848099028737 --base 200

должен разложить на 3111111191 и 3111114407

Как ваще работает - если смотришь что прога долго работает и пробегает много
итераций (по логам) то увеличиваешь --base - тогда одна итерация будет длится
дольше но уже будет больше вероятности итерации найти решение


****************************************************

6 лаба:

EllipticAlgs/

открываем sign_make.py находим класс SignParams пишем туда параметры из своего варианта

python sign_make.py --path-file res/test.docx --d *закрытый ключ например 5719*

появится подпись файла res/test.docx.sign

ее можно красиво посмотреть утилитой
dumpasn1 res/test.docx.sign

проверка подписи
python sign_check.py --path-file res/test.docx --path-sign res/test.docx.sign

должна быть надпись что подпись верная
