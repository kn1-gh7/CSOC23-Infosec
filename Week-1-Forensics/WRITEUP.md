
# Writeups for Week-1 Forensics

---

### Strings it

##### Challenge Desription:

My favourite instruments are **string** type instruments. They sound so goooood.

[Challenge File](chall0)

##### Writeup:

The hint in this challenge was supposed to be **string** which directly points towards using the `strings` command. You should first try with `grep`. 

```shell
kn1gh7@ctfbox:-$ strings chall0 | grep CSOC23
CSOC23{5tr1ng5_4r3_c00l}
```

Thus you get the flag as **`CSOC23{5tr1ng5_4r3_c00l}`**

---

### The "Bytes" Challenge

##### Challenge Desription:

My friend keeps on crying about a parrot **"byte"**, but come on how **significant** can it be? What are your **comments** on this?

[Challenge File](chall1.png)

##### Writeup:

The keywords in this chall are **byte** which refers to **bytes**, **significant** and **comments**. Listing the procedures we know in our mind, we can see that the hints point to **User Comment** in exif data and **LSB (Least Significant Bytes) Steganography Technique**.

First running `exiftool` on the image file.

```shell
kn1gh7@ctfbox:-$ exiftool chall1.png | grep -i comment
User Comment : https://pastebin.com/LTKRQBtK
```

The [pastebin link](https://pastebin.com/LTKRQBtK) is password protected. So now we have to decode LSB data from the image file. I usually like to use [zsteg](https://github.com/zed-0xff/zsteg) for this, but you can use any tool or even make your own script.

```shell
kn1gh7@ctfbox:-$ zsteg chall1.png 
imagedata           .. file: MIPSEL-BE MIPS-III ECOFF executable not stripped - version 0.1
b1,r,lsb,xy         .. text: "Cr[~{>`"
b1,b,lsb,xy         .. file: OpenPGP Secret Key
b1,rgb,lsb,xy       .. text: "y0u_f0uNd_m3_h4ck3r"
b2,r,msb,xy         .. text: ["U" repeated 20 times]
b2,g,msb,xy         .. text: "PUUUUUUUUUUUUUU"
b2,b,msb,xy         .. text: "UUPUUUPPUU"
b2,rgb,lsb,xy       .. file: PGP Secret Sub-key -
b2,rgb,msb,xy       .. text: ["U" repeated 12 times]
b2,bgr,msb,xy       .. text: ["U" repeated 12 times]
b2,rgba,lsb,xy      .. file: PGP Secret Sub-key -
b2,abgr,msb,xy      .. text: ["W" repeated 16 times]
b4,r,lsb,xy         .. text: "\"\"\"DDDDDff"
b4,r,msb,xy         .. text: "DDD\"\"\"\"\"ff"
b4,g,lsb,xy         .. text: "\"334UUUfv"
b4,g,msb,xy         .. text: "D$$\"\"$\"\"ff"
b4,b,lsb,xy         .. file: Targa image data - Map (291-4096) 1 x 256 x 1 +529 +51 ""
b4,b,msb,xy         .. text: "$\"\"bffff"
b4,rgb,msb,xy       .. text: "C4\"'r\"'r\"Grb'"
b4,bgr,msb,xy       .. text: "2D#2\"'r\"'rBgr&g"
b4,abgr,msb,xy      .. text: "2O4/2/r/r/r/r/tororo"
```

We can see the string `"y0u_f0uNd_m3_h4ck3r"`, putting it in as pastebin password, we get the flag **`CSOC23{p4rr0t_by735_4r3_d4Ng3r0u5}`**

---

### Cakewalk

##### Challenge Desription:

My friend **John** just challenged me to find hidden flag in this image. When I asked for a hint he just said it would be a cakewalk and sang the famous song **"We will rock you.."**. Can you help me find the flag?

[Challenge File](chall2)

##### Writeup:

The keywords are cake**walk** which refers to **binwalk**, **John** which refers to **John the Ripper** and **"We will rock you.."** which refers to **rockyou.txt** wordlist.

We first use [binwalk](https://github.com/ReFirmLabs/binwalk) on the image.

```shell
kn1gh7@ctfbox:-$ binwalk chall2
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 640 x 853, 8-bit/color RGB, non-interlaced
59            0x3B            Zlib compressed data, best compression
978460        0xEEE1C         Zip archive data, encrypted at least v1.0 to extract, compressed size: 41, uncompressed size: 29, name: do_not_open_me.txt
978681        0xEEEF9         End of Zip archive, footer length: 22
```

We see it contains a zip file so we extract the image using `binwalk -e chall2` and change the directory to `_chall2.extracted`. On listing its contents, we see a txt file named `do_not_open_me.txt` and a zip file(`EEE1C.zip` in my case).

`cat do_not_open_me.txt` does not give any output, meaning the zip file has to be extracted. On trying to unzip the zip file, we are prompted for a password.

To crack the password we use [`John the Ripper`](https://github.com/openwall/john) and [`rockyou.txt`](https://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=&cad=rja&uact=8&ved=2ahUKEwjE1oWR2cT_AhW5VmwGHSaHDKUQFnoECAYQAQ&url=https%3A%2F%2Fgithub.com%2Fbrannondorsey%2Fnaive-hashcat%2Freleases%2Fdownload%2Fdata%2Frockyou.txt&usg=AOvVaw3snAERl1mU6Ccr4WFEazBd) file.

```shell
kn1gh7@ctfbox:-$ zip2john EEE1C.zip > zip.hashes
ver 1.0 efh 5455 efh 7875 EEE1C.zip/do_not_open_me.txt PKZIP Encr: 2b chk, TS_chk, cmplen=41, decmplen=29, crc=4ABFB750 ts=0B17 cs=0b17 type=0
kn1gh7@ctfbox:-$ john --wordlist=rockyou.txt zip.hashes
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
1337HaX0r        (EEE1C.zip/do_not_open_me.txt)     
1g 0:00:00:02 DONE (2023-06-15 12:42) 0.4166g/s 5534Kp/s 5534Kc/s 5534KC/s 134178..1325436987
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

We see the password was `"1337HaX0r"`, we unzip the zip file using the password and then read the do_not_open_me.txt file to get the flag as **`CSOC23{bRu73_f0rc3_y0uR_w4y}`**

---

### Magic Everywhere

##### Challenge Desription:

Do your **magic** and find the flag and I might share some of my dogecoins with you :D. Remember to always see the **bigger picture**.

[Challenge File](chall3)

##### Writeup:
After downloading the chall file, we try to find the file type by running the `file` command.
```shell
kn1gh7@ctfbox:-$ file chall3
chall3: JPEG image data
```
We see that the file is of JPEG type but when we try to open it with an image viewer, it says that the marker is not supported (sometimes the file is corrupted, depending on viewer). Here the keyword **magic** which refers to magic bytes which define the file type. A quick [google search](https://en.wikipedia.org/wiki/List_of_file_signatures) and you will find that magic bytes for JPEG image is `FF D8 FF E0 00 10 4A 46 49 46 00 01`. Editing it and we are able to open the image file now.

![Image](https://github.com/kn1-gh7/CSOC23-Infosec/blob/main/Week-1-Forensics/writeup-files/s1.jpg?raw=true)

Hmmm...The second keyword is about **bigger picture**, so we try to increase height of the image. Again searching for how to do it we get this [article](https://cyberhacktics.com/hiding-information-by-changing-an-images-height/). Upon reading we increase the required hex value randomly a few times.
On setting the height bytes as `01 c0`, we are able to see the flag.

![Image](https://github.com/kn1-gh7/CSOC23-Infosec/blob/main/Week-1-Forensics/writeup-files/s2.jpg?raw=true)

Thus, the flag is **`CSOC23{7h3_w0rLd_15_m4g1caL}`**

---

### Never Gonna Give you Up

##### Challenge Desription:

Time to get rickrolled...or maybe not ? **See through** this Rick Astley's masterpiece to find out.

[Challenge File](chall4)

##### Writeup:

```shell
kn1gh7@ctfbox:-$ file chall4
chall4: Zip archive data, at least v2.0 to extract, compression method=deflate
kn1gh7@ctfbox:-$ unzip chall4                            
Archive:  chall4
  inflating: chall4.wav
kn1gh7@ctfbox:-$ audacity chall4 
```
The keyword, **see through**, probably refers to seeing..but in spectrogram view as mentioned in resources. You can use any spectrogram viewer..I am using audacity.
In spectrogram mode, we see that we have some text but its very small.

![Image](https://github.com/kn1-gh7/CSOC23-Infosec/blob/main/Week-1-Forensics/writeup-files/s3.png?raw=true)

So we go to spectrogram settings and change min freq to 5000 and max freq to 15000 and are able to read the flag after zooming in.

![Image](https://github.com/kn1-gh7/CSOC23-Infosec/blob/main/Week-1-Forensics/writeup-files/s4.png?raw=true)

Thus, the flag is **`CSOC23{n0t_r34lly_4_r1ckr0ll_huh?}`**

---

### Go Deeper

##### Challenge Desription:

How **deep** would you go for this flag? btw random info - I use same username and **passwords** in my logins. I really like the alias `kn1gh7` lol.

[Challenge File](chall5)

##### Writeup:

```shell
kn1gh7@ctfbox:-$ file chall5
chall5: Zip archive data, at least v2.0 to extract, compression method=deflate
kn1gh7@ctfbox:-$ unzip chall5                           
Archive:  chall5
  inflating: chall5.wav
```

The keyword **deep** refers to the tool deepsound (windows only tool), and the other hints refer that the password might be **kn1gh7**

We get the flag.txt file which has the flag: **`CSOC23{th4t5_wh4t_5h3_5a1d}`**

---

### Baby Shark

##### Challenge Desription:

I sniffed on **gROoTh47er's** network and here is the captured data. Can you find something useful? [Checkout this awesome video](https://youtu.be/XqZsoesa55w)

[Challenge File](chall6)

##### Writeup:

Just keep on reading the packets and you come across a packet with data as `r$~rabL3c3J0D9cC<N`. The name **gROoTh47er's** has `ROT47` in it which implies the string is encoded in ROT 47. Decrypting it using any [tool](https://www.dcode.fr/rot-47-cipher) we get the flag: **`CSOC23{b4by_sh4rk}`**

---

### Planet Morse

##### Challenge Desription:

Musk mElon keeps on talking about this weird planet **Morse**. Here's an audio in this language. Does it make any sense? *Ignore flag format and just write what you get*

[Challenge File](chall7)

##### Writeup:


```shell
kn1gh7@ctfbox:-$ file chall7
chall7: Zip archive data, at least v2.0 to extract, compression method=deflate
kn1gh7@ctfbox:-$ unzip chall5                           
Archive:  chall7
  inflating: chall7.wav
```

The keyword **Morse** refers to morse code. Decode the audio manually if you want to take up a challenge! or just use an [online tool](https://morsecode.world/international/decoder/audio-decoder-adaptive.html)
You get the flag: **`C S O C 2 3 L 3 T 5 G 0 T 0 M 0 R S 3`**
