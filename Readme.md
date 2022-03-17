!!! если в каком то месте в любой лабе шифрование/расшифрование 
       проходит с ошибкой то не генерим ключи а просто берем мои из res/
       на них все работает проверял сто раз не пишите по хуйне !!!!


1 лаба:
в victim/

генерим ключи

python rsa_gen_keys.py --path-out-private res/rsa_private.key \
       --path-out-public res/rsa_public.key


python gen_session_key.py --path-out res/data.key

шифруем файл

python encrypt.py --path-in res/1.pdf \
       --rsa-key res/rsa_public.key --data-key res/data.key

расшифровываем

python decrypt.py --path-in res/1.pdf.encrypted --rsa-key \
       res/rsa_private.key

Расшифрованный должен совпасть с исходным

Подписываем файл

python sign.py --path-in res/1.pdf --rsa-key res/rsa_private.key

Проверяем подпись

python sign_check.py --path-in res/1.pdf --path-sign \
       res/1.pdf.sign --rsa-key res/rsa_public.key

Должна быть надпись что подпись верная

****************************************************

2 лаба:
в attacker/

3 атки:                   

python main.py --attack 1

python main.py --attack 2

python main.py --attack 3

если пишет что атака не прошла запускаем пока не пройдет

и генерация параметров

python main.py --generate [BIT_SIZE напр. 512]
(512 битные ключи генерятся секунды 3-4, если больше то возможно долго ждать придется)

****************************************************

3 лаба:

атака в attacker/

python main.py --attack 4

и шифрование в victim/
шифруем

python encrypt_oaep.py --path-in res/1.pdf --rsa-key res/rsa_public.key \
       --data-key res/data.key

и расшифровываем

python decrypt_oaep.py --path-in res/1.pdf.encrypted --rsa-key \
       res/rsa_private.key


тут может вылезти ошибка incorrect ciphertext. Если поймаем ее - заново шифруем
       и заново расшифровываем. Такое бывает, в алгоритме есть рандомизация шифр-
       текст всегда разный

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

python sign_make.py --path-file res/test.docx --path-sign res/sign.hex \
       --d *закртый ключ например 719* --path-open-key res/public.key

появится подпись файла res/sign.hex

ее можно красиво посмотреть утилитой
dumpasn1 res/sign.hex

проверка подписи
python sign_check.py --path-file res/test.docx --path-sign res/sign.hex \
       --path-open-key res/public.key

должна быть надпись что подпись верная
