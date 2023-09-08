# qCTF

Systems Induction CTF

Here's the solutions for all the problems hosted for the CTF:

### Q1_FlagFinder

Given the text cipher: "4e6a41774e6d777a4e56396d4d484a665a6d77304e6c39754e47307a4e513d3d"

the first thing to notice is that this is hex code. Converting this to text yields: "NjAwNmwzNV9mMHJfZmw0Nl9uNG0zNQ=="

This is a basic Base64 encoding. Convert base64 to text and the result yields out to: "6006l35_f0r_fl46_n4m35" and hence the final flag is "CTF{6006l35_f0r_fl46_n4m35}"

### Q2_Video

An extremely basic file information question. Opening the file and checking the video information in the comments section gives you the flag:

![Rick Roll](https://github.com/Dashlander/qCTF/blob/main/rickroll.png)

### Q3_BinaryBounty

The original intention was to introduce everyone to reverse engineering. Basically, since the compiled binary when executed asks for a passphrase, the answer must be stored in the programme. Doing so using Ghidra, will yield strings, one of which is "superstrongpassword". Using this when asked for a passphrase, prints out: "CTF{1mm4_h4ck3rm4nn_n0w}" which is the flag.

However, this was simply bypassed by many by opening the binary in VSCode. Most of the data is unreadable, but the flag and the strings themselves are viewable. I did see many incorrect submissions from people who simply copied the compiled versions of the flag string as "CTF{1mm4H�_h4ck3rmH��@���H��H���H�h4ck3rm4H�nn_n0w}" or other various itertation of the same. When opening the binary executable as a text file, the encoding that text editors use are primarily UTF-8 and ASCII. This means that changing the binary representation of special characters like @, !, _ can result in the text editor misrepresenting the data. So even if you were to simply open the file, you would still need to check for the only unchanged string which was "superstrongpassword".

### Q4_Conversion

Given a message file that is 37 KiBs of text, the challenge description states that this was received from a popular audio company. Viewing the file contents, this is again a base64 encoding. Decode this base64 to audio, and it will be an audio file which seems unintelligible. Reversing this audio will output "dumb_audio_flag". Thus, the flag is "CTF{dumb_audio_flag}"

### Q5_HideYourSecrets

The key thing to notice is that the attached text file is a keylog. The file contains records of actions. key press ID and key release ID, which log individual key actions. Figuring out which ID corresponds to which key, using various [tables](https://gist.github.com/rickyzhang82/8581a762c9f9fc6ddb8390872552c250) or doing post processing on the file. The flag comes out to be "CTF{w31rd_flag}"

### Q6_Spectral_Secret
The given file has .npy extension, a quick google search tells you its a numpy file. Unlock the harmonic taperstry of signal indicates that a signal has probably been stored in the .npy file. 
Next we will load the file using:
```python
import numpy as np
data = np.load('spectral_secret.npy')
```
next we inspect its shape
```python
print("Array shape:", data.shape)
print("Data type:", data.dtype)
```
presence of two dimensional array with complex data type can give you the hint that maybe its the fft of a 2d signal.
finally we test it out using:
```python
reconstructed_image = np.fft.ifft2(data)

# Convert the reconstructed image to uint8
reconstructed_image = np.real(reconstructed_image).astype(np.uint8)

# Display the reconstructed image
cv2.imshow('Reconstructed Image', reconstructed_image)
cv2.waitKey(0)
cv2.destroyAllWindows()
```
This gives the final Flag "CTF{m3_1z_pr0}"

### Q7_Really Simple Algorithm
To start of we got an RSA (Really Simple Algorithm lol). This can be found out we have a numeric key along with it. The algorithm to solve it is given below.
The public exponent e is such that gcd(f(n), e) = 1; 1 < e < f (n) 
The public modulus n is the product of two primes
Calculate p, q, two prime numbers, the basis of the keys
Calculate f(n) = (p-1)(q-1) [The totient function]
Calculate d, such that ed mod f(n) = 1

p = 5929487
q = 1775867
n = 10529980290229
f(n) = 10529972584876
e = 129834683
d = 4930488347963

private key = {4930488347963, 10529980290229}
and public key = {129834683, 10529980290229}
```python
#Code to calculate the private key (in python):
def extended_gcd(a, b):
    if b == 0:
        return a, 1, 0
    gcd, x, y = extended_gcd(b, a % b)
    return gcd, y, x - (a // b) * y

def find_private_key(public_key, p, q):
    n = p * q
    phi_n = (p - 1) * (q - 1)

    gcd, d, _ = extended_gcd(public_key, phi_n)
    if gcd != 1:
        return None  # No private key exists for the given public key and primes

    private_key = d % phi_n
    return private_key

# Insert values; Note: public key here means only the public exponent
public_key = 129834683
p = 5929487
q = 1775867

private_key = find_private_key(public_key, p, q)
if private_key is not None:
    print("Private key:", private_key)
else:
    print("No private key exists for the given public key and primes.")

#Code to decrypt the encrypted message:
def decrypt_rsa(ciphertext, private_key):
    decrypted_message = ""
    n, d = private_key
    for c in ciphertext:
        m = pow(c, d, n)
        decrypted_message += chr(m)
    return decrypted_message

# Private key
private_key = (10529980290229, 4930488347963)

# Encrypted message
ciphertext = [6448485280296, 4683776938738, 9577089513307, 6888093682969, 9019339071410, 246189401736, 5139025648676, 9409769051528, 780685933709, 1471462085731, 4683776938738, 780685933709, 6888093682969, 6478775835003, 780685933709, 6062412063462, 6243860990272, 353906583386, 780685933709, 9577089513307, 688247530411, 2362286149030]

# Decrypt the message
decrypted_message = decrypt_rsa(ciphertext, private_key)

print("Decrypted Message:", decrypted_message)
```
### Q8_What does the server say?

As given in the description, a leaking port  on the server is what must be checked for. This can be done in two ways. First is to simply type "139.59.26.242:20632", where the browser connects to the particular IP and its port.

![Mom help, someone DDOSed my terminal!](https://github.com/Dashlander/qCTF/blob/main/ddosmyterminal.png?raw=true)

This was only possible due to the question being setup in such a way so that the output could be viewed in a browser. The second way, is to connect to the IP and the port using terminal utilities such as netcat and forwarding that output to a text file. The flag obtained is : "CTF{m0r3_7r0ubl3_7h4n_175_w0r7h}"

Made by [@Dashlander](https://github.com/Dashlander), [@Shreyans](https://github.com/ShreyansJain04), [@Viraj](https://github.com/TheBinaryCoder1000101)
