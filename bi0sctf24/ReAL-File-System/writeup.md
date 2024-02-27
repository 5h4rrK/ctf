## Writeup

Description 

###### Here are some extra materials you might find useful

- [Deletion Pattern in ReFS](https://www.sciencedirect.com/science/article/pii/S2666281723001191?ref=pdf_download&fr=RR-2&rr=857d87e5a8047866)

- [Forensic Analysis of ReFS Journaling](https://www.sciencedirect.com/science/article/pii/S2666281721000342?ref=pdf_download&fr=RR-2&rr=857d87e5a8037866)

- [Reverse Engineering of ReFS](https://www.sciencedirect.com/science/article/pii/S1742287619301252?ref=pdf_download&fr=RR-2&rr=858e699298bd7868)

- [Awesome ReFS Investigation tool](https://github.com/horensic/ARIN)

- [ReFS Detector](https://github.com/jamemanionda/ReFS_Detector)

### Fix FileSystem

![alt text](assests/image-104.png)

![alt text](assests/image-106.png)

![alt text](assests/image-109.png)

![alt text](assests/image-107.png)

`Cluster Size : 0x1000`

![alt text](assests/image-101.png)

![alt text](assests/image-102.png)

![alt text](assests/image-103.png)

![alt text](assests/image100.png)

![alt text](assests/image.png)

- Everything is working fine when loading it into `Active Disk Editor`

![alt text](assests/image-200.png)

![alt text](assests/image-105.png)

## LogFile-Structure

![alt text](assests/image-201.png)

### LogFile Entry Structure

![alt text](assests/image-202.png)

## Explanation

![alt text](assests/image-204.png)

> Red Bounded Area -> `ReFS Entry Header`

> Green Bounded Area -> `Log Entry Header `

![alt text](assests/image-205.png)

![alt text](assests/image-207.png)

### Redo Log Header

![alt text](assests/image-208.png)

`Redo Log Header Size : 0x38 bytes`

### Redo Data Offset Array

![alt text](assests/image-209.png)

`Tail Offset` : _indicates ending of data offset array_

`Tail Size`: _size of each transaction_

### Redo Transactional Data

## Example 1

![alt text](assests/image-210.png)

## Example 2

![alt text](assests/image-211.png)

![alt text](./assests/image-212.png)
_Figure Source: ARIN_

#### Extracting Log Files from the File System

```bash
dd if=ReAL_File_System.001 skip=$((0x20001000)) count=$((0x200A7000 -0x20001000)) of=logs.txt bs=1
```

## Question-1

1. List all directories that have been renamed, including their original names and the timestamps of when they were renamed.

   > **Format :[ ['OriginalDirName', 'RenamedDirName', TimeStamp] , .. ]**

<details>
    <summary> Directory Renamed Opcodes</summary>

```
0x2 -> 0x2 -> 0x1 -> 0x1 -> 0x4
```

</details>

![alt text](assests/image-38.png)

![alt text](assests/image-39.png)

Timestamp will be found in next `MLog` (starting with opcode `0x4`).

![alt text](assests/image-55.png)

![alt text](assests/image-40.png)

`['e88e52cac', '88077a4a1370', '2024-02-18 13:10:20.49']`

Similarly,
`['fb828d071', 'cad090f9724d', '2024-02-18 13:12:12.48']`

**Final Ans**

```py
    [
        ['e88e52cac', '88077a4a1370', '2024-02-18 13:10:20.49'],
        ['fb828d071','cad090f9724d', '2024-02-18 13:12:12.48']
    ]

```

2. Name all the deleted directories with deletion timestamps.

   > **Format : [ ['DirectoryName' , 'TimeStamp'] , .. ]**

<details>
    <summary> Permanent Directory Deletion Opcodes</summary>

```bash
0x2 -> 0xf -> 0x2 -> 0xf -> 0x4 -> 0x12
```

</details>

![alt text](assests/image-44.png)

![alt text](assests/image-41.png)

Next, the remaining opcodes can be found in `MLog`.

![alt text](assests/image-42.png)

![alt text](assests/image-43.png)

**Permanently Deleted Directories**

```py
[
     ['f8f1c218f9', '2024-02-18 13:11:28.57'],
     ['de34f60ab',  '2024-02-18 13:13:19.60']
]
```

<details>
    <summary> Simple Directory Deletion Opcode</summary>

```bash
P(Directory Creation) → 0x06 → 0x04 → 0x04 → 0x04 → 0x04 → 0x03 → 0x02 → 0x02 → 0x01 → 0x01 → 0x0e → 0x04 → 0x03 → 0x04 → 0x04 → 0x04 → 0x01 → 0x04 → 0x03 → 0x04 → 0x04 → 0x08
```

</details>

![alt text](./assests/image-213.png)

![alt text](assests/image-45.png)

![alt text](assests/image-50.png)

![alt text](assests/image-52.png)

![alt text](assests/image-48.png)

![alt text](assests/image-46.png)

![alt text](assests/image-47.png)

```py
 ('c062fb828', '2024-02-18 13:10:48.62')
```

OR,

Simple Deletion Timestamp can be found through analyzing `$IXXXXX`

![alt text](./assests/image-214.png)

![alt text](./assests/image-215.png)

**Final Ans**

```py
[
     ['f8f1c218f9', '2024-02-18 13:11:28.57'],
     ['de34f60ab',  '2024-02-18 13:13:19.60'],
     ['c062fb828',  '2024-02-18 13:10:48.62']
]
```

### Question -3

---

3. List all directories with their creation times, including renamed and deleted.

   > **Note : If a directory was renamed, include its original name and creation time.**

   > **Fomat : [ ['DirectoryName' , 'CreatedTime'] , .... ]**

<details>
    <summary> Dir Creation</summary>

```bash
0x00→0x00→0x04→0x10→0x01→0x01→0x01→0x0e→0x03→0x04
```

</details>

![alt text](assests/image-53.png)

![alt text](assests/image-54.png)

![alt text](assests/image-56.png)

**_Final Ans_**

```py
    [
        ['de34f60ab', '2024-02-18 13:06:59.22'],
        ['e88e52cac', '2024-02-18 13:07:31.13'],
        ['fb828d071', '2024-02-18 13:08:13.88'],
        ['f8f1c218f9','2024-02-18 13:08:40.58'],
        ['c062fb828', '2024-02-18 13:09:14.55'],
        ['bb6de6190', '2024-02-18 13:09:34.00']
    ]
```

### Question - 4

---

4. Recover the files that have been deleted, and provide the **md5sum** of each recovered file.

   > **Format : [ '[filehash1]' , '[filehash2]', ... ]**

Load the disk image in `Active Disk Editor`

![alt text](assests/image-57.png)

- `$IXXXXX` file has components like filename, fullpath , deletion time etc.

- `$RXXXXX` file contents can be recovered.

- 3 files are simply deleted.

![alt text](assests/image-59.png)

![alt text](assests/image-60.png)

![alt text](assests/image-58.png)

```bash
dd if=ReAL_File_System.001 skip=$(((0x1000 * 71168)/1)) count=$(((0x15a)/1))  bs=1 of=simple-pass.txt

dd if=ReAL_File_System.001 skip=$(((0x1000 * 68608)/16)) count=$(((0x04e20)/16))  bs=16 of=19ff211f

dd if=ReAL_File_System.001 skip=$(((0x1000 * 70144))) count=$(((0x041b7)))  bs=1 of=fe0c329
```

```py
f91488b7e00c31793bd7aa98c51896d0  simple-pass.txt
4c009b045056af8f9bb401c69408d2cf  19ff211f
c50c5bcb9e98537e3d63df1bc68a81d0  fe0c329
```

**_Final Ans_**

```py
    [
        ['f91488b7e00c31793bd7aa98c51896d0'],
        ['4c009b045056af8f9bb401c69408d2cf'],
        ['c50c5bcb9e98537e3d63df1bc68a81d0']
    ]
```

### Question - 5

---

5. Identify all files that have been deleted (Simple + Permanent), including their deletion timestamps.

   > **Format :[ [ 'filename' , 'TimeStamp' , 'Simple/Permanent' ] , .. ]**

**_Simple Deletion_**

![alt text](assests/image-63.png)

**_Permanent Deletion_**

![alt text](assests/image-62.png)

![alt text](assests/image-61.png)

#### simple-pass.txt

![alt text](assests/image-64.png)

![alt text](assests/image-66.png)

![alt text](assests/image-67.png)

TimeStamp

![alt text](assests/image-68.png)

`2024-02-18 13:15:00.51`

Analyze it for every other files.

```py
['simple-pass.txt','2024-02-18 13:15:00.51','Simple'],
['19ff211f','2024-02-18 13:14:31.43','Simple'],
['fe0c329','2024-02-18 13:15:52.49','Simple']
```

#### For Permanent Files

```bash
0x0f->0x02->0x0f->0x02->0x04
```

![alt text](assests/image-69.png)

![alt text](assests/image-70.png)

```bash
('ead47cb','2024-02-18 13:19:26.69','Permanent')
('essay.txt','2024-02-18 13:18:22.47','Permanent')

```

**_Final Ans_**

```py
    [
        ['simple-pass.txt','2024-02-18 13:15:00.51','Simple'],
        ['19ff211f','2024-02-18 13:14:31.43','Simple'],
        ['fe0c329','2024-02-18 13:15:52.49','Simple'],
        ['ead47cb','2024-02-18 13:19:26.69','Permanent'],
        ['essay.txt','2024-02-18 13:18:22.47','Permanent']
    ]
```

## Question-6

6. Restore all encrypted files, decrypt them, and provide the **md5sum** of each decrypted file after removing any extra bytes before computing the hash.

   > **Format :[['hash1'], ['hash2'],..]**

### An Overview on time_update.exe

---

- First, Enumerates each directory and rename all the files.
- Then, Generates a random time and changes it to `SystemToFileTime` and generates `key1` and adds 4 bytes nonce
- Takes md5sum of `key1` and set it as `key2`
- Again rename each file with random time and then encrypts the file
- **Encryption** : `enc[i] = file[i] ^ key1[i] ^ key2[i]`
- Lastly, enumerate all files and updates the file names with `tort` extension.
- Before exiting, again updates the system time to initial time.

![alt text](./assests/image-216.png)
![alt text](./assests/image-217.png)
![alt text](./assests/image-218.png)
![alt text](./assests/image-219.png)
![alt text](./assests/image-220.png)
![alt text](./assests/image-221.png)
![alt text](./assests/image-222.png)
![alt text](./assests/image-223.png)

> Opcode for Renamed File : **`0x02 → 0x05 → 0x01 → 0x04 → 0x04`**

- Let's manually search for the required information. We'll begin by assigning filenames with the extension `tort` and then conduct a search within the log file. 

- Specifically, we'll focus on identifying the first operation code (opcode) located at offset `0xb0`. 

- After locating it, we'll parse the data and examine the previous MLog to find the corresponding filenames.



![alt text](assests/image-1.png)

![alt text](assests/image-2.png)

![alt text](assests/image-3.png)

First Rename : _`15005-39026.pdf -> bf2f63b3`_

Search for the _`bf2f63b3`_

![alt text](assests/image-5.png)

![alt text](assests/image-6.png)

![alt text](assests/image-7.png)

Second Rename : _`bf2f6b3 -> 0cf51fbc`_

> Sets the current system time and date. The system time is expressed in Coordinated Universal Time (UTC).

Rename Time(Encryption Key) : _`2010-02-26 12:38:43.0000000 `_

```
Enc Key : 2010 2 2 26 12 38 43 0
```

![alt text](assests/image-8.png)

Third Rename : _`0cf51fbc -> 0cf51fbc.tort`_

> **Similarly, locate the encryption timestamp for all other files and then extract those files.**

`binary-01.gif -> c7982ef6 -> a917438f -> a917438f.tort` : **1995 2 2 27 2 11 42 0**

`Everest Vista.webp -> d406327c -> 3a7fab71 -> 3a7fab71.tort ` : **1990 8 2 28 21 6 35 0**

`Paranormal Phenomenon.docx -> 830c92a3 -> bb292337 -> bb292337.tort` : **1993 7 2 16 17 10 46 0**

`so-cappy.jpg -> 141e0f79 -> 24819686 -> 24819686.tort ` : **2001 4 2 19 8 27 45 0**

`stuffs.rar -> f15ebcd2 -> 7a6c7166 -> 7a6c7166.tort` : **2009 11 2 22 17 5 55 0**

`ySq12b0T.mp4 -> 86c66c9c -> 185c65f8 -> 185c65f8.tort` : **2007 7 2 28 3 27 33 0**

` vl36hkjkzbh91.png -> 313feb6e -> cc876a3b -> cc876a3b.tort` : **1985 3 2 4 16 23 53 0**

---

![alt text](./assests/image-224.png)

### Carving Out Files

###### 0cf51fbc.tort

Let's take a look at it using Active Disk Editor.

![alt text](assests/image-20.png)

![alt text](assests/image-21.png)

![alt text](assests/image-22.png)

```bash
dd if=ReAL_File_System.001 skip=$(((0x10e94000)/4096)) count=$(((0x16c000)/4096))  bs=4096 of=0cf51fbc_1.tort

dd if=ReAL_File_System.001 skip=$(((0x11001000)/4096)) count=$(((0x141000)/4096))  bs=4096 of=0cf51fbc_2.tort

cat 0cf51fbc_1.tort 0cf51fbc_2.tort > 0cf51fbc.tort
```

###### a917438f.tort

```bash
dd if=ReAL_File_System.001 skip=$(((0x10025000)/64)) count=$(((0x89ce40)/64))  bs=64 of=a917438f.tort
```

After extracting the encrypted files, remove any additional bytes.


![alt text](assests/image-28.png)

---

###### 7a6c7166.tort

![alt text](assests/image-30.png)

![alt text](assests/image-29.png)

![alt text](assests/image-32.png)

Go to offset `0x108c2000`, `0x10c05000` & read `830 * 0x1000` ,`130 * 0x1000`bytes respectively

```bash
 dd if=ReAL_File_System.001 skip=$(((0x108c2000)/8192)) count=$(((830 * 0x1000)/8192))  bs=8192 of=7a6c7166_1.tort

 dd if=ReAL_File_System.001 skip=$(((0x10c05000)/4096)) count=$(((130 * 0x1000)/4096))  bs=4096 of=7a6c7166_2.tort

cat 7a6c7166_1.tort 7a6c7166_2.tort > 7a6c7166.tort
```

---

###### 185c65f8.tort

```bash
dd if=ReAL_File_System.001 skip=$(((68743 * 0x1000)/4096)) count=$(((525 * 0x1000)/4096))  bs=4096 of=185c65f8.tort
```

---

###### 24819686.tort

```bash
dd if=ReAL_File_System.001 skip=$(((0x12800000)/4096)) count=$(((0x10000)/4096))  bs=4096 of=24819686.tort
```

---

###### 3a7fab71.tort

```bash
dd if=ReAL_File_System.001 skip=$(((0x10000000)/4096)) count=$(((0x25000)/4096))  bs=4096 of=3a7fab71.tort
```

---

###### bb292337.tort

```bash
dd if=ReAL_File_System.001 skip=$(((0x13a00000)/4096)) count=$(((0x8000)/4096))  bs=4096 of=bb292337.tort
```

---

###### cc876a3b.tort

```bash
dd if=ReAL_File_System.001 skip=$(((0x1000 * 72705))) count=$((0x175f))  bs=1 of=cc87a3b.tort
```

###### Remove extra bytes from the files.

```py
import struct

file_names = ['0cf51fbc.tort','a917438f.tort','7a6c7166.tort','185c65f8.tort','24819686.tort','3a7fab71.tort','bb292337.tort','cc876a3b.tort']

for _ in file_names:
    buff = bytes()
    file = open(_, 'rb')
    sig = file.read(0x04)
    sz = struct.unpack("<I", file.read(0x04))[0]
    buff += file.read(sz)
    open(f"{_}", 'wb').write(sig + sz.to_bytes(4,'little') + buff)

```

![alt text](assests/image-24.png)

```cpp
#include <iostream>
#include <stdint.h>
#include <string>
#include <Windows.h>
using namespace std;

#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

int main(int argc , char * argv[]){
    SYSTEMTIME st;
    FILETIME ft;
    st.wYear =  (int16_t) stoi(argv[1]);
    st.wMonth =  (int16_t) stoi(argv[2]);
    st.wDayOfWeek = (int16_t)stoi(argv[3]);
    st.wDay =  (int16_t) stoi(argv[4]);
    st.wHour =  (int16_t) stoi(argv[5]);
    st.wMinute = (int16_t) stoi(argv[6]);
    st.wSecond =  (int16_t) stoi(argv[7]);
    st.wMilliseconds =  (int16_t) stoi(argv[8]);

    SystemTimeToFileTime(&st, &ft);
    cout << ft.dwLowDateTime << " : " << ft.dwHighDateTime<< ":";
    int64_t low = ROTATE_LEFT(static_cast<int64_t>(ft.dwLowDateTime), 4);
    int64_t high = ROTATE_LEFT(static_cast<int64_t>(ft.dwHighDateTime) , 3);
    cout << low  << ":" <<  high;
    return 0;
}

```

- Generate the 4 bytes nonce.

```bash
 crunch 4 4 "0123456789abcdef\!#&*%GHIJ-lm+_"  > passwd.txt
```

### File Decryption Script

```py
import os
import hashlib

MAPPINGS = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', '!', '#', '&', '*', '%', 'G', 'H', 'I', 'J', '-', 'l', 'm', '+', '_']

class Extensions:
    PNG = b"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A"
    JPG = b"\xff\xd8\xff"
    JPG_END = b"\xff\xd9"
    WEBP = b"RIFF\x08\x4E\x02\x00" ## [4:8] -> file size
    RAR = b"\x52\x61\x72\x21\x1A"
    GIF = b"\x47\x49\x46\x38\x39\x61"
    MP4 = b'ftyp'
    ZIP = b"\x50\x4B\x03\x04\x14\x00\x06\x00"
    PDF = b'%PDF-1.'

def check_header(buff, key, ext):
    dec = Decryptor()
    temp_key2 = hashlib.md5(key).hexdigest().encode()

    if ext == 'png':
        res = dec(encbuff=buff[: len(Extensions.PNG)], key1=key, key2=temp_key2)
        if res == Extensions.PNG : return True

    if ext == 'jpg':
        res = dec(encbuff=buff[: len(Extensions.JPG)], key1=key, key2=temp_key2)
        if res[:3] == Extensions.JPG:
            res = dec(encbuff=buff, key1=key, key2=temp_key2)
            if(res[-2:] == Extensions.JPG_END and (b'EXIF' in res.upper() or b'JFIF' in res)): return True

    if ext == 'webp':
        res = dec(encbuff=buff[: len(Extensions.WEBP)], key1=key, key2=temp_key2)
        if res == Extensions.WEBP: return True

    if ext == 'rar':
        res = dec(encbuff=buff[: len(Extensions.RAR)], key1=key, key2=temp_key2)
        if res == Extensions.RAR: return True

    if ext ==  'gif':
        res =dec(encbuff=buff[: len(Extensions.GIF)], key1=key, key2=temp_key2)
        if res == Extensions.GIF: return True

    if ext  == 'zip' or ext == 'docx':
        res =dec(encbuff=buff[: len(Extensions.ZIP)], key1=key, key2=temp_key2)
        if res == Extensions.ZIP: return True

    if ext == 'mp4':
        res =dec(encbuff=buff[:32], key1=key, key2=temp_key2)
        if res[4:8] == Extensions.MP4:
            res =dec(encbuff=buff, key1=key, key2=temp_key2)
            if (b'moov' in res and b'mdat' in res): return True

    if ext == 'pdf':
        res = dec(encbuff=buff[:7], key1=key, key2=temp_key2)
        if res == Extensions.PDF: return True

def encrypt(val):
    rounds = 16
    delta = 0x1A2B693C
    sumval = 0x00000000
    keys =  [0x1234f, 0x1bc0d, 0x80112, 0x4ef50]
    v0, v1 = 0, val
    for _ in range(rounds):
        sumval += (delta)
        v0 = (((( (v1 << 4) + keys[0]) ^ (v1 + sumval + keys[1]) ^ ((v1 >> 5) )) + keys[3]) & 0xffffffff)
        v1 = v0
    val = v0
    return val

def get_key1(val, key):
    while(val > 0):
        key += MAPPINGS[val % 30].encode()
        val //= 30
    return key

def md5digestString(a): return hashlib.md5(a).hexdigest().encode()

class Decryptor(object):

    def __init__(self) -> None:
        self.key1 : bytes  = None
        self.key2 : bytes = None

    def update_keys(self, key1 , key2) -> None:
        self.key1 = key1
        self.key2 = key2

    def decrypt(self, encbuff: bytes) -> None:
        self.buffer = bytearray(len(encbuff))
        for _ in range(len(self.buffer)):
            self.buffer[_] = (encbuff[_] ^ self.key1[_ % len(self.key1)] ^ self.key2[_ % len(self.key2)])

    def __call__(self, key1 : bytes , key2 : bytes , encbuff : bytes) -> bytearray:
        if self.key1 == None or self.key2 == None:
            self.update_keys(key1=key1, key2=key2)
        self.decrypt(encbuff=encbuff)
        return self.buffer


if __name__ == "__main__":

    base_dir = "encrypted/"
    files = ['0cf51fbc.tort','a917438f.tort','3a7fab71.tort', 'bb292337.tort', '24819686.tort', '7a6c7166.tort', '185c65f8.tort', 'cc876a3b.tort']
    ext = ['pdf','gif', 'webp', 'docx', 'jpg', 'rar', 'mp4', 'png']
    dec_files = ['15005-39026.pdf','binary-01.gif','Everest Vista.webp','Paranormal Phenomenon.docx','so-cappy.jpg','stuffs.rar','ySq12b0T.mp4','vl36hkjkzbh91.png']

    time_exe = "/mnt/e/filetime.exe"  ## Compiled exe path
    timestamps = ["2010 2 2 26 12 38 43 0",'1995 2 2 27 2 11 42 0', '1990 8 2 28 21 6 35 0','1993 7 2 16 17 10 46 0','2001 4 2 19 8 27 45 0','2009 11 2 22 17 5 55 0','2007 7 2 28 3 27 33 0','1985 3 2 4 16 23 53 0']

    for _ in range(0,len(files)):
        w = Decryptor()
        print("File : ", dec_files[_])
        enc_buff = open(f"{base_dir}{files[_]}", "rb").read()[8:]
        key1 = b""
        t = timestamps[_].split(" ")
        out = os.popen(f"{time_exe} {t[0]} {t[1]} {t[2]} {t[3]} {t[4]} {t[5]} {t[6]} {t[7]}").read()
        out = out.split(":")
        out = [int(_) for _ in out]
        key1 += get_key1((out[3] & 0xffffffff), b'')
        key1 += get_key1((out[2] & 0xffffffff) , b'')
        key1 += get_key1((encrypt((out[2] + out[3]) & 0xffffffff)) , b'')
        key1 += get_key1((encrypt((out[2] * out[3]) & 0xffffffff)) , b'')
        key1 += get_key1((encrypt((out[2] & out[3]) & 0xffffffff)) , b'')
        nonce = None
        if nonce == None:
            passw = open("passwd.txt", "r")
            while(t:= passw.readline().strip()):
                temp = key1 + t.encode()
                status = check_header(
                    enc_buff, temp,ext[_]
                    )
                if status == True:
                    nonce = t.encode()
                    print(f'[+] Found for {files[_]} :: nonce : {nonce} key1 : {key1.decode()}{nonce.decode()}')

        key1 += nonce
        key2 = hashlib.md5(key1).hexdigest().encode()
        dec = w(encbuff=enc_buff, key1= key1, key2= key2)
        open(f"decrypted/{dec_files[_]}", 'wb').write(dec)

```

![alt text](assests/image-37.png)

```js
da8ed3e98eb5a2ba769ea60b48b0f6eb  15005-39026.pdf
d58621ce6e560ba1c045892aef0b5f8b  binary-01.gif
683092bd6640e62a3dc49b412da4fe71  Everest Vista.webp
11d9788ce48371a6ef230892ada1554d  Paranormal Phenomenon.docx
bc9a53c83976e9779bce2d0635f1bbbe  so-cappy.jpg
111fb8624db9365af79e6ec446b00eac  stuffs.rar
76675928a19bcc5602ef81c7a833d3fa  vl36hkjkzbh91.png
4d9c5a006c4315625c86d94a8fd9fd2e  ySq12b0T.mp4
```

### Final Ans

```js
[
  ['da8ed3e98eb5a2ba769ea60b48b0f6eb'],
  ['d58621ce6e560ba1c045892aef0b5f8b'],
  ['683092bd6640e62a3dc49b412da4fe71'],
  ['11d9788ce48371a6ef230892ada1554d'],
  ['bc9a53c83976e9779bce2d0635f1bbbe'],
  ['111fb8624db9365af79e6ec446b00eac'],
  ['76675928a19bcc5602ef81c7a833d3fa'],
  ['4d9c5a006c4315625c86d94a8fd9fd2e'],
]
```
