## Password Manager Command Line Tool

This repo is a local password manager command line tool. 
It uses AES-256-GCM encryption to store passwords with a 12 byte iv, 
and uses PBKDF2 with HMAC-SHA256 in order to convert the master password plus a 16 byte salt value into a key. 
While I have designed this password manager to be secure to the best of my ability, 
this repo was primarily created as a project for a college class, 
so I would recommend that anyone interested in using it review the code in order to 
make sure that it is up to their standards of security. 

## Setup

In order to start using this repo, first ensure that you have version 8 or later of the Java JDK installed on your device.
Then download PasswordManager.java, SafePasswordList.java, and SafeCharList.java into an empty directory on your device.
After this, use your desired command line application to navigate into the directory containing the downloaded files and 
run the following command to compile the password manager:
```
javac -d out PasswordManager.java SafePasswordList.java SafeCharList.java
```
Once the password manager is compiled, you can run it from the directory you placed it in via:
```
java -cp out PasswordManager
```

## Usage

In order to use the password manager, first run it using the command specified in the above section. 
If this is the first time you ran the password manager or if you do not have password\_vault.enc file in your current directory,
you will be prompted to create a new master password which is what you will use to access any passwords that you store in the password manager.
If you already ran the password manager and have a password\_vault.enc file in your current directory, 
you will instead be prompted to enter the master password that you created previously.

Once you use your password to enter into the password manager, you will be presented with several different functions:
1. `add` prompts you to enter a password name \(what you reference the password by\), username, and password value,
and adds this to your saved passwords
2. `view` displays a list of the names of all your passwords
3. `get` \(WIP\)
4. `master` \(WIP\)
5. `exit` saves all newly entered passwords to the database and then exits the password manager. 
This is the proper way to close the program and ensures that any newly added passwords are saved to the database and that any sensative encryption/decrytion related data stored in memory is overwriten. 

