When connected to ```pwn.institute:36224``` we are presented with very limited shell, no many commands you can directly type in.

```python
exec_whitelist = ['exit', 'echo', 'ls']
cmd_whitelist = ['help', '?', 'quit', 'sign_command']
```

Script ```cryptsh``` is showing ```cmd_whitelist``` of commands that can be directly typed in.

```bash
marko@kali:~/Desktop/task$ python3 cryptsh
CryptoShell v 0.0.1
> help

Documented commands (type help <topic>):
========================================
exec  help  quit  sign_command

Undocumented commands:
======================
echo

> 
```

Surely most interesting is ```sign_command``` which by looking into ```cryptsh``` source is letting you to execute extra ```exec_whitelist```, where of course ```ls``` is most interesting.

```bash
> sign_command ls -l
ns3t0iRKPnkBOKh1fA3YuxVgmzjcplU43ZFiFDrLEJUGL/0BtWc3AetS7XWQm+cC
> ns3t0iRKPnkBOKh1fA3YuxVgmzjcplU43ZFiFDrLEJUGL/0BtWc3AetS7XWQm+cC
ls -l
total 8
-rw-r--r-- 1 marko marko 2709 Sep 29 16:07 cryptsh
-rw-r--r-- 1 marko marko   25 Sep 29 15:49 flag
> 
```

And there immediately we are clear with direction where this goes: try to ```cat flag``` somehow, although ```cat``` is not in either of whitelists.

```python
def do_sign_command(self, args):
        """ Create a signature for a selected whitelist of allowed commands (for testing purposes)"""
        data = args.split(' ', 1)
        cmd = data[0]
        args = data[1] if 1 < len(data) else ''
        if cmd in exec_whitelist:
            line = 'exec {} {}'.format(cmd, shlex.quote(args))
            print(self.cipher.encrypt(line).decode())
```

One desperate move would be to try to break exec syntax: ```exec [-cl] [-a name] [command [arguments]]```, and execute ```cat flag``` after ```ls```.
Unfortunately (or in most cases fortunately) ```shlex.quote()``` is doing proper sanitization and it showed up in practice to be perfectly safe to use, so whatever you write after
```sign_command ls```, will end up as single argument to ```ls```, and no way you can force ```exec``` to print out flag. This failure would be expected as we are dealing with crypto task.

```python
    def encrypt(self, raw):
        iv=get_random_bytes(BLOCK_SIZE)
        raw = pad(raw.encode(), BLOCK_SIZE)
        c_mac = AES.new(self.key, AES.MODE_CBC, iv)
        mac = c_mac.encrypt(raw)[-BLOCK_SIZE:]
        c_enc = AES.new(self.key, AES.MODE_CTR, nonce=iv[:-CTR_SIZE])
        data = c_enc.encrypt(raw)
        return b64encode(iv + data + mac )
    def decrypt(self, enc):
        enc = b64decode(enc)
        iv = enc[:BLOCK_SIZE]
        mac = enc[-BLOCK_SIZE:]
        data = enc[BLOCK_SIZE:-BLOCK_SIZE]
        c_enc = AES.new(self.key, AES.MODE_CTR, nonce=iv[:-CTR_SIZE])
        message = c_enc.decrypt(data)
        c_mac = AES.new(self.key, AES.MODE_CBC, iv)
        mac_check = c_mac.encrypt( message )[-BLOCK_SIZE:]
        if mac != mac_check:
            return "Mac Error!"
        else:
            return unpad(message, BLOCK_SIZE).decode('utf8', 'backslashreplace')
```

From here onwards I am staring into cypher functions, trying to spot security hole, as description of task is stating that there is one in existence.

Encrypted command is composed of 3 parts: 
1. IV used in CBC mode to generate MAC that is actually last block of ciphertext generated from ```exec exec_whitelist sanitized_argument``` (```iv```).
2. Ciphertext generated in CTR mode with ```iv[0:12]``` as nonce, and 4 bytes counter starting with 0 (```data```).
3. MAC as described in 1 (```mac```).

We need to get deeper into understanding these modes and possibly spot opportunity. 

![](https://github.com/markich88/BalCCon2k20_cryptsh/blob/main/OUT.png)

*Cipher block chaining (CBC)*

![](https://github.com/markich88/BalCCon2k20_cryptsh/blob/main/IN.png)

*Counter (CTR)*

Looking these schemes there is interesting observation - we are able to get output of CTR decryption as ```OUT = plaintext XOR cyphertext```, and therefore we can get ciphertext
of whatever plaintext we want without knowing key (```SECRET```). So it is possible to change encrypted command to match whatever plaintext command we want. The problem remaining is how to match MAC that is generated with CBC encryption mode. Changing plaintext will generate new MAC, and there we can't do a lot except maybe in first block of CBC MAC generation - we have control over initialization vector (IV), and since we know that ```IN = plaintext XOR IV```, we know how to set IV for new plaintext to generate correct IN.
Still MAC generation would not be correct, because we would have different plaintext in second block, so we need to restrict ourselves on changing plaintext in first block only. Do we have everything covered? No. Changing IV would change nonce that is used in CTR. But nonce is using only first 12 bytes of IV, so changing last 4 bytes of IV would be only acceptable option, which in turn means we are allowed to change only last 4 bytes of first block of plaintext. 

![](https://github.com/markich88/BalCCon2k20_cryptsh/blob/main/Slika1.png)

*Position of bytes of failed command in ciphertext, with bytes susceptible to change in purple*

Command can be as long as we like, but needs to be crafted in such way that only modifications on byte offsets ```0xc```, ```0xd```, ```0xe```, ```0xf``` will give us flag output.

One would expect job is done with spotting this security hole, but crafting input that we should send on signing, and getting encrypted command which can be modified to produce flag output showed up to be more difficult then what I thought in beginning. Perhaps I was overlooking solution as well. Surely we want to avoid ```shlex.quote()``` inserting quotes, as they are party breaker, putting a lot of damage as you need to unquote command that should generate flag output and for that almost certainly you will need more space then 4 bytes spread. One very good example I arrived with was ```exec echo 'cat *|sh'```  generated with ```sign_command echo cat *|sh```, where idea was to replace ```|sh'``` with ```'|sh```, so I would manage to fix quoting but this replacement would start with offset 0x10, i.e. just with start of second block. Finally I am coming with solution, ```exec echo cat *|sh```, generated with ```sign_command echo catfissh```, that will create plaintext ```exec echo catfissh``` without quotes since we are not using space nor special characters. Now we need to replace ```fis``` with ```[space]*|``` which are 3 bytes on offsets ```0xd```, ```0xe```, ```0xf```.

```bash
marko@kali:~/Desktop/task$ python3 cryptsh
CryptoShell v 0.0.1
> sign_command echo catfissh
+INDjaxNsZEpg++OHi6ulSivKhuulAFq4FlmZpbZn74IXBMLyYQjEea5ppd0Ko1KMAfUo14cHeXWOOPlOJSVtQ==
> +INDjaxNsZEpg++OHi6ulSivKhuulAFq4FlmZpbZn74IXBMLyYQjEea5ppd0Ko1KMAfUo14cHeXWOOPlOJSVtQ==
echo catfissh
catfissh
>   
```

First starting with getting encryption of crafted command.

```python
>>> from base64 import b64encode, b64decode
>>> command_b64 = '+INDjaxNsZEpg++OHi6ulSivKhuulAFq4FlmZpbZn74IXBMLyYQjEea5ppd0Ko1KMAfUo14cHeXWOOPlOJSVtQ=='
>>> 
>>> command_enc = b64decode(command_b64)
>>> iv = command_enc[0:16]
>>> data = command_enc[16:-16]
>>> mac = command_enc[-16:]
>>> 
>>> len(data)                                                                            
32                                                                                                  
>>> ctext_ctr = data[0:16]
>>> ptext_ctr = 'exec echo catfis'      #first block of plaintext
>>> OUT = bytes([b1 ^ b2 for b1, b2 in zip(ctext_ctr, ptext_ctr.encode())])
>>> OUT
b'\x1cD\xe7F\x03\xfcB\xdf\x8d\x01\xb2\xd8\xceZQ_'
>>> ptext_ctr_want = 'exec echo cat *|'
>>> ctext_ctr_want = bytes([b1 ^ b2 for b1, b2 in zip(OUT, ptext_ctr_want.encode())])
>>> ctext_ctr_want
b'y<\x82%#\x99!\xb7\xe2!\xd1\xb9\xbaz{#'
>>> 
```

Here we are getting crafted ciphertext for first block of data, so now we need to fix IV to give proper IN of CBC MAC computation.

```python
>>> 
>>> IN = bytes([b1 ^ b2 for b1, b2 in zip(iv, ptext_ctr.encode())])
>>> iv_cbc_want = bytes([b1 ^ b2 for b1, b2 in zip(IN, ptext_ctr_want.encode())])
>>> iv_cbc_want
b'\x03\xa5\x08\x08\xfe\x81a\x17\xb5|\xe9+\x1fJ\xed\xea'
>>> 
```

New IV is generated. Rests to connect all the pieces together:

```python
>>> b64encode(iv_cbc_want+ctext_ctr_want+data[16:32]+mac)
b'+INDjaxNsZEpg++OHmjtmiivKhuulAFq4FlmZpaf3LEIXBMLyYQjEea5ppd0Ko1KMAfUo14cHeXWOOPlOJSVtQ=='
```
And execute newly crafted command.

```bash
> +INDjaxNsZEpg++OHmjtmiivKhuulAFq4FlmZpaf3LEIXBMLyYQjEea5ppd0Ko1KMAfUo14cHeXWOOPlOJSVtQ==
echo cat *|sh
#!/usr/bin/env python3
from hashlib import md5
from Crypto.Cipher import AES

.....

            return unpad(message, BLOCK_SIZE).decode('utf8', 'backslashreplace')
if __name__ == "__main__":
    cs = CryptoShell()
    cs.prompt = '> '
    cs.cmdloop('CryptoShell v 0.0.1')
flag{here_goes_the_flag}
> 
```
