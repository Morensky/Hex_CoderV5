from PIL import Image
import colorama
import numpy as np
import os.path
from math import ceil
from random import randrange
#===================================================
'''first Kuznechik'''
#===================================================
# Функция XOR для двух строк
def xor_func (input1AsString, input2AsString, in_code = 16):
    input1AsInteger = int(input1AsString, in_code)
    input2AsInteger = int(input2AsString, in_code)
    result = input1AsInteger ^ input2AsInteger
    resultAsHex = hex(result)
    resultAsHex = resultAsHex.upper()
    resultAsHex = resultAsHex[2:]
    if len(resultAsHex) != len(input1AsString):
        for i in range(len(input1AsString) - len(resultAsHex)):
            resultAsHex = '0' + resultAsHex
    return resultAsHex

# Функция перевода между системами счисления
def convert_base(num, to_base = 10, from_base = 10):
    # Преобразование в десятичное число
    if isinstance(num, str):
        n = int(num, from_base)
    else:
        n = int(num)
    # Преобразование десятичного числа в необходимую систему счисления
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    if n < to_base:
        return alphabet[n]
    else:
        return convert_base(n // to_base, to_base) + alphabet[n % to_base]

# Ряд Галуа
galua_coef = [148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1]
galua_coef_reverse = [1, 148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148]
# Таблица степеней двойки
galua_fields = [1, 2, 4, 8, 16, 32, 64, 128, 195, 69, 138, 215, 109, 218, 119, 238, 31, 62, 124, 248, 51, 102, 204, 91, 182, 175, 157, 249, 49, 98, 196, 75, 150, 239, 29, 58, 116, 232, 19, 38, 76, 152, 243, 37, 74, 148, 235, 21, 42, 84, 168, 147, 229, 9, 18, 36, 72, 144, 227, 5, 10, 20, 40, 80, 160, 131, 197, 73, 146, 231, 13, 26, 52, 104, 208, 99, 198, 79, 158, 255, 61, 122, 244, 43, 86, 172, 155, 245, 41, 82, 164, 139, 213, 105, 210, 103, 206, 95, 190, 191, 189, 185, 177, 161, 129, 193, 65, 130, 199, 77, 154, 247, 45, 90, 180, 171, 149, 233, 17, 34, 68, 136, 211, 101, 202, 87, 174, 159, 253, 57, 114, 228, 11, 22, 44, 88, 176, 163, 133, 201, 81, 162, 135, 205, 89, 178, 167, 141, 217, 113, 226, 7, 14, 28, 56, 112, 224, 3, 6, 12, 24, 48, 96, 192, 67, 134, 207, 93, 186, 183, 173, 153, 241, 33, 66, 132, 203, 85, 170, 151, 237, 25, 50, 100, 200, 83, 166, 143, 221, 121, 242, 39, 78, 156, 251, 53, 106, 212, 107, 214, 111, 222, 127, 254, 63, 126, 252, 59, 118, 236, 27, 54, 108, 216, 115, 230, 15, 30, 60, 120, 240, 35, 70, 140, 219, 117, 234, 23, 46, 92, 184, 179, 165, 137, 209, 97, 194, 71, 142, 223, 125, 250, 55, 110, 220, 123, 246, 47, 94, 188, 187, 181, 169, 145, 225, 1]

# Линейное преобразование для блока длины 32
def linear_transformation(num, move = 'straight'):
    # Подставляемое число, если число, образованное 2-мя подряд идущими цифрами в 16-ой системе счисления, равно 0
    numIfNull = 257

    # Линейная функция выполняется 16 раз
    for i in range(16):
        # Массив индексов таблицы степеней двойки `galua_fields` коэффициентов ряда Галуа
        coefs = []
        # Массив индексов таблицы степеней двойки `galua_fields`, полученных от чисел, образованных 2-мя подряд идущими цифрами в 16-ой системе счисления
        nums = []

        # Заполнение массивов
        for j in range(len(galua_coef)):
            if move == 'reverse':
                coefs.append(galua_fields.index(galua_coef_reverse[ len(galua_coef_reverse) - j - 1 ]))
            else:
                coefs.append(galua_fields.index(galua_coef[ len(galua_coef) - j - 1 ]))
            if int(convert_base(num[j * 2 : j * 2 + 2], from_base=16)) == 0:
                nums.append(numIfNull)
            else:
                nums.append(galua_fields.index(int(convert_base(num[j * 2 : j * 2 + 2], from_base=16))))

        # Массив значений, полученных из таблицы степеней двойки `galua_fields`
        galua = []

        # Заполнение массива
        for j in range(len(galua_coef)):
            if nums[j] != numIfNull:
                # Проверка, что сумма индексов не более длины таблицы степеней двойки `galua_fields`
                if nums[j] + coefs[j] <= 255:
                    galua.append(galua_fields[nums[j] + coefs[j]])
                else:
                    galua.append(galua_fields[(nums[j] + coefs[j]) % 255])

        # Подсчитывание числа, которое необходимо прибавить к концу входного блока
        galua_num = galua[0]
        if len(galua) != 1:
            for j in range(len(galua) - 1):
                # XOR массива значений, полученных из таблицы степеней двойки `galua_fields`
                galua_num = int(xor_func(str(galua_num), str(galua[j + 1]), in_code = 10), 16) % 256
        galua_num = hex(galua_num)[2:]
        # Проверка, если длина полученного числа равна 1
        if len(str(galua_num)) == 1:
            galua_num = '0' + str(galua_num)

        # Сдвиг с добавлением полученного числа
        if move == 'reverse':
            num = galua_num + num[:len(num)-2]
        else:
            num = num[2:] + galua_num
    return num

# Таблица для прямого хода (straight)
nonlinear_coef = [252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77, 233, 119, 240, 219, 147, 46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193, 249, 24, 101, 90, 226, 92, 239, 33, 129, 28, 60, 66, 139, 1, 142, 79, 5, 132, 2, 174, 227, 106, 143, 160, 6, 11, 237, 152, 127, 212, 211, 31, 235, 52, 44, 81, 234, 200, 72, 171, 242, 42, 104, 162, 253, 58, 206, 204, 181, 112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156, 183, 93, 135, 21, 161, 150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178, 177, 50, 117, 25, 61, 255, 53, 138, 126, 109, 84, 198, 128, 195, 189, 13, 87, 223, 245, 36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185, 3, 224, 15, 236, 222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74, 167, 151, 96, 115, 30, 0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65, 173, 69, 70, 146, 39, 94, 85, 47, 140, 163, 165, 125, 105, 213, 149, 59, 7, 88, 179, 64, 134, 172, 29, 247, 48, 55, 107, 228, 136, 217, 231, 137, 225, 27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144, 202, 216, 133, 97, 32, 113, 103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82, 89, 166, 116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57, 75, 99, 182]
# Таблица для обратного хода (reverse)
nonlinear_coef_reverse = [165, 45, 50, 143, 14, 48, 56, 192, 84, 230, 158, 57, 85, 126, 82, 145, 100, 3, 87, 90, 28, 96, 7, 24, 33, 114, 168, 209, 41, 198, 164, 63, 224, 39, 141, 12, 130, 234, 174, 180, 154, 99, 73, 229, 66, 228, 21, 183, 200, 6, 112, 157, 65, 117, 25, 201, 170, 252, 77, 191, 42, 115, 132, 213, 195, 175, 43, 134, 167, 177, 178, 91, 70, 211, 159, 253, 212, 15, 156, 47, 155, 67, 239, 217, 121, 182, 83, 127, 193, 240, 35, 231, 37, 94, 181, 30, 162, 223, 166, 254, 172, 34, 249, 226, 74, 188, 53, 202, 238, 120, 5, 107, 81, 225, 89, 163, 242, 113, 86, 17, 106, 137, 148, 101, 140, 187, 119, 60, 123, 40, 171, 210, 49, 222, 196, 95, 204, 207, 118, 44, 184, 216, 46, 54, 219, 105, 179, 20, 149, 190, 98, 161, 59, 22, 102, 233, 92, 108, 109, 173, 55, 97, 75, 185, 227, 186, 241, 160, 133, 131, 218, 71, 197, 176, 51, 250, 150, 111, 110, 194, 246, 80, 255, 93, 169, 142, 23, 27, 151, 125, 236, 88, 247, 31, 251, 124, 9, 13, 122, 103, 69, 135, 220, 232, 79, 29, 78, 4, 235, 248, 243, 62, 61, 189, 138, 136, 221, 205, 11, 19, 152, 2, 147, 128, 144, 208, 36, 52, 203, 237, 244, 206, 153, 16, 68, 64, 146, 58, 1, 38, 18, 26, 72, 104, 245, 129, 139, 199, 214, 32, 10, 8, 0, 76, 215, 116]

# Нелинейное преобразование (шифр простой замены)
def nonlinear_transformation(num, move = 'straight'):
    for i in range(16):
        # Выбор таблицы для хода
        if move == 'reverse':
            nonlinear_table = nonlinear_coef_reverse
        else:
            nonlinear_table = nonlinear_coef

        # Выборка пары цифр, которые будут заменены в соответствии с таблицей `nonlinear_coef` или `nonlinear_coef_reverse`
        num_for_replace = num[i * 2 : i * 2 + 2]
        # Преобразование числа через таблицы хода
        convert_num = convert_base(num_for_replace, to_base = 10, from_base = 16)
        num_for_replace = convert_base(nonlinear_table[int(convert_num)], to_base = 16, from_base = 10)
        if len(num_for_replace) == 1:
            num_for_replace = '0' + num_for_replace

        # Возврат числа
        num = num[: i * 2] + num_for_replace + num[i * 2 + 2:]
    return num
#===================================================
'''second Kuznechik'''
#===================================================
def Keybuilding(X, S, L, key): #создание ключа
    C = [] # константы
    F = [] # ячейки Фейстеля    
    K = [key[:int(len(key) / 2)], key[int(len(key) / 2) :]]
    for i in range(32):
        if len(hex(i + 1)[2:]) == 1:
            C.append(L('0' + hex(i + 1)[2:] + '000000000000000000000000000000').upper())
        else:
            C.append(L(hex(i + 1)[2:] + '000000000000000000000000000000').upper())
    # формирование ячеек Фейстеля
    F.append([ K[1], X(L(S(X( K[0], C[0]))),  K[1])])
    for i in range(32):
        K = [ F[i][1], X(L(S(X( F[i][0], C[i]))),  F[i][1])]
        F.append(K)
    # разбиение заданного ключа пополам
    K = [key[:int(len(key) / 2)], key[int(len(key) / 2) :]]
    # формирование новых ключей из ячеек Фейстеля
    for i in range(len(F)):
        if (i + 1) % 8 == 0:
            K.append(F[i][0])
            K.append(F[i][1])    
    return K

def Encrypt(X, S, L, texttoencode, key): #шифрование блоков байтов
    K = Keybuilding(X, S, L, key)
    for i in range(9):
        texttoencode = L(S(X(texttoencode, K[i])))
    texttoencode = X(texttoencode, K[9])
    return texttoencode

def Decrypt(X, S, L, texttodecrypte, key): #дешифровка блоков байтов
    K = Keybuilding(X, S, L, key)
    for i in range(9, 0, -1):
        texttodecrypte = S(L(X(texttodecrypte, K[i]), 'reverse'), 'reverse')
    texttodecrypte = X(texttodecrypte, K[0])
    return texttodecrypte

def KeyGeneration():
    keypiece = []
    for i in range(32):
        keypiece.append(format(randrange(0, 255), '02X'))
    key = "".join(keypiece)
    return key
##===========================================================================
'''def libary pixl'''
##===========================================================================
def sizeinfo(AllData): #определение размерности картинки
    sizedata = len(AllData)
    y = ceil((3*sizedata)**0.5 / 4) 
    x = ceil((16/9)*y) 
    return x, y

def truelenginfo(lenginfo): #преобразование длины исходных данных в набор пиксельных данных формата RGB
    lengslayer = []
    while lenginfo > 0:
        lengslayer.append(lenginfo % 256)
        lenginfo = lenginfo // 256
    for i in range(12 - len(lengslayer)):
        lengslayer.append(0)
    return lengslayer

def typefileinfo(file_name): #определение и сохранение в байтах расширения исходных данных
    resulttype, typ = [], []
    f = file_name.split('.')
    typename = bytearray(f[-1], 'utf-8')
    for i in range(len(typename)):
        resulttype.append(typename[i])
    typ = resulttype
    for i in range(3-len(resulttype)%3):
        resulttype.append(0)
    return resulttype, typ

def lengofTFI(file_name): #преобразование длины расширения в набор пиксельных данных формата RGB
    typ, slayOftyp = typefileinfo(file_name)[1], []
    lengtyp = len(typ)
    while lengtyp > 0:
        slayOftyp.append(lengtyp % 256)
        lengtyp = lengtyp // 256
    for i in range(6 - len(slayOftyp)):
        slayOftyp.append(0)    
    return slayOftyp    

def info_file(file_name, lenginfo): #создания линии данных на основе вышенайденного
    info_lengdata, info_typefile, info_lengtypedata = truelenginfo(lenginfo), typefileinfo(file_name)[0], lengofTFI(file_name)
    resultinfo = info_lengdata + info_lengtypedata + info_typefile
    resultinfo.append(0)
    for i in range(3-len(resultinfo)%3):
        resultinfo.append(0)
    return resultinfo
##===========================================================================
'''def libary unpixl'''
##===========================================================================
def searchdatainfo(pixeldata): # поиск расширения и длины данных
    expansionline, truthlength, lengExpline, preexpansionline = [], [], [], []
    init, counter = 0, 0
    for i in range(12, 18): #поиск длины расширения
        if pixeldata[i] != 0:
            lengExpline.append(pixeldata[i])
    for i in range(len(lengExpline)): #перевод из байтового в 10ричное
        init += lengExpline[i]*(256**i)
    for i in range(18, len(pixeldata)):#поиск имени расширения данных
        if counter != init:
            preexpansionline.append(pixeldata[i])
            counter +=1
        else:
            break
    for i in range(len(preexpansionline)): #дополнительная проверка
        if preexpansionline[i] != 0:
            expansionline.append(preexpansionline[i])
    for i in range(12): #поиск длины данных
        truthlength.append(pixeldata[i])
    return expansionline, truthlength, init

def searchstartpoint(pixeldata): #поиск точки старта обработки
    lengexpansion = searchdatainfo(pixeldata)[2]
    return 21+ceil(lengexpansion)
##===========================================================================
'''PIXELATION'''
##===========================================================================
def PIXL(file_name, X, S, L): #кодирование файла в картинку RGB
    key = KeyGeneration()#генерация ключа
    ##{=========================================================================}
    fileData, pixData, EncodedData, DecodedData = [], [], [], []
    file = open(file_name, 'rb') #чтение файла
    while (byte := file.read(1)):
        fileData.append(byte[0])
    file.close
    lengdata = len(fileData) #исходная длина данных
    infoData = info_file(file_name, lengdata) #получение списка данных 
    AllData = infoData + fileData
    for i in range(48-len(AllData)%48): #доводение до кратности 16 и 3
        AllData.append(randrange(0, 255))
    for i in range(len(AllData)//16): #блочное шифрование данных
        toEncodeData = []
        for j in range(16):
            toEncodeData.append(format(AllData[i*16+j], '02X'))
        texttoencode = "".join(toEncodeData)
        encodedtext = Encrypt(X, S, L, texttoencode, key)
        EncodedData.append(encodedtext)
    for i in range(len(EncodedData)):
        textencrypted = EncodedData[i]
        for j in range(16):
            DecodedData.append(int(textencrypted[j*2]+textencrypted[j*2+1], 16))
    width, leng = sizeinfo(DecodedData)[1], sizeinfo(DecodedData)[0] #получение размеров картинки
    for i in range(leng*width*3 - len(DecodedData)): #заполняем остатки для формирования картинки
        DecodedData.append(randrange(0, 255))
    for i in range(width): #формируем трехмерный список, создавая тем самым каркас картинки
        linepix = []
        for j in range(leng):
            point = (i*leng+j)*3
            pix = (DecodedData[point], DecodedData[point+1], DecodedData[point+2])
            linepix.append(pix)
        pixData.append(linepix)
    array = np.array(pixData, dtype=np.uint8) # окончательное формирование картинки
    new_image = Image.fromarray(array)
    file_key = open('key_note' + '.txt', 'w')#запихиваем картинку
    file_key.write(key)
    file_key.close()
    return new_image.save('pxl' + str(randrange(1, 10000000)) + '.png')
##===========================================================================
'''UNPIXELATION'''
##===========================================================================
def UNPIXL(file_name, X, S, L): #декодирование данных, содержащиеся в картинке
    keyfile = open('key_note.txt', 'r') #открытие и чтение 
    key = keyfile.read()
    keyfile.close()
    ##============================
    im = Image.open(file_name, 'r') #открытие и чтение картинки
    length, width = im.size 
    pixelData = list(im.getdata()) 
    im.close()
    DataImage, DecodedData, DecryptedData = [], [], []
    fulldata, init, counter = [], 0, 0
    for i in range(width*length): #переход из многомерного в одномерный массив
        for j in range(3):
            DataImage.append(pixelData[i][j])
    for i in range(len(DataImage)//16): #дешифровка данных на основе зашифрованных данных и ключа
        ToDecrypte = []
        for j in range(16):
            ToDecrypte.append(format(DataImage[i*16+j], '02X'))
        texttodencrypte = "".join(ToDecrypte)
        decryptedtext = Decrypt(X, S, L, texttodencrypte, key)
        DecryptedData.append(decryptedtext)
    for i in range(len(DecryptedData)): #перевод в 10-ое из 16-го
        piece = DecryptedData[i]
        for j in range(16):
            DecodedData.append(int(piece[j*2]+piece[j*2+1], 16))
    lengdata, expansionline, startpoint = searchdatainfo(DecodedData)[1], searchdatainfo(DecodedData)[0], searchstartpoint(DecodedData) #получение данных для декодировки
    file_extension = bytearray(expansionline).decode() # получаем расширение данных
    for i in range(len(lengdata)): #исходная длина данных
        init += lengdata[i] * (256 ** i)
    for i in range(startpoint, len(DecodedData)): #сборка данных
        if counter != init:
            fulldata.append(DecodedData[i])
            counter +=1
        else:
            break
    file_out = open('result' + str(randrange(1, 10000000)) + '.' + file_extension, 'wb') #получаем исходный файл с его данными
    file_out.write(bytearray(fulldata))  
    file_out.close()
    return 'Complite'
##===========================================================================
'''Main Commands'''
##===========================================================================
colorama.init()
print("\033[3;32;40m                      _        _                                             \033[0;32;40m")
print("\033[3;32;40m                     | |      | |                                            \033[0;32;40m")
print("\033[3;32;40m  _ __ ___   __ _  __| | ___  | |__  _   _   _ __ ___   ___  _ __ ___ _ __   \033[0;32;40m")
print("\033[31m | '_ ` _ \ / _` |/ _` |/ _ \ | '_ \| | | | | '_ ` _ \ / _ \| '__/ _ \ '_ \  \033[31m")
print("\033[31m | | | | | | (_| | (_| |  __/ | |_) | |_| | | | | | | | (_) | | |  __/ | | | \033[31m")
print("\033[3;32;40m |_| |_| |_|\__,_|\__,_|\___| |_.__/ \__, | |_| |_| |_|\___/|_|  \___|_| |_| \033[0;32;40m")
print("\033[3;32;40m                                      __/ |                                  \033[0;32;40m")
print("\033[3;32;40m                                     |___/                                   \033[0;32;40m")
print('\033[31m --|{HEX CODER V5}|-- \033[31m')
print('\033[5;37;40m choose the type of script \033[0;37;40m')
print('\033[31m 1 -- encode file to png \033[31m')
print('\033[31m 2 -- decode png to file \033[31m')
print('\033[3;32;40m {My contacs: discord - Herman Garsky#2574 \033[3;32;40m')
print('\033[3;32;40m              telegram - https://t.me/morenskytm} \033[3;32;40m')
X = xor_func # операция XOR
S = nonlinear_transformation # нелинейное преобразование в режиме простой замены
L = linear_transformation # линейное преобразование
while True:
    choose = int(input(' num type: ')) 
    if choose == 1:
        print(PIXL(input(' write address file or namefile here >>> '), X, S, L))
        print("\033[5;37;40m take care of your key!!! otherwise, you risk losing access to the image data \033[0;37;40m")
        print('Complite')
    elif choose == 2:
        print(UNPIXL(input(' write address picture or namepicture here >>> '), X, S, L))
    else:
        break        