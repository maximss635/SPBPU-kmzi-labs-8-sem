python encrypt.py --path-in res/1.pdf --rsa-key res/rsa_public.key --data-key res/data.key
python decrypt.py --path-in res/1.pdf.encrypted --rsa-key res/rsa_private.key
mv res/1.pdf.encrypted.decrypted res/1.pdf.encrypted.decrypted.pdf

python encrypt.py --path-in res/2.txt --rsa-key res/rsa_public.key --data-key res/data.key
python decrypt.py --path-in res/2.txt.encrypted --rsa-key res/rsa_private.key
mv res/2.txt.encrypted.decrypted res/2.txt.encrypted.decrypted.txt