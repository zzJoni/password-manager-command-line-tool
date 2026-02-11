// Encryption/decryption
import javax.crypto.SecretKeyFactory;
import javax.crypto.SecretKey;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import javax.security.auth.DestroyFailedException;
import javax.crypto.AEADBadTagException;
import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;

// Input/Output
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.File;
import java.util.Scanner;
import java.io.IOException;

// Byte conversions
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

// Other
import java.util.Arrays;


public class PasswordManager implements AutoCloseable{
    // Initialize global inputs and files
    private final BufferedReader inputCharReader = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
    private final Scanner inputScanner = new Scanner(System.in, StandardCharsets.UTF_8);
    private final File passwordVault = new File("password_vault.enc");
    private final File tempPasswordVault = new File("temp_password_vault.enc");

    // Stores passwords
    private final SafePasswordList passwords = new SafePasswordList();
    char[] masterPassword;

    // Stores global variables necessary for creating the master key
    private static final int VERSION_NUMBER = 1; // Stores the version of the vault file
    private static final int SALT_SIZE = 16;
    private static final int IV_SIZE = 12;
    private static final int GCM_TAG_SIZE = 16*8; // 128 bits
    private static final int MASTER_KEY_SIZE = 32*8; // 256 bits
    private static final int KEY_GENERATOR_ITERATION_COUNT = 600_000;

    // Stores cryptography related classes
    private static final SecureRandom random = new SecureRandom();
    private final SecretKeyFactory keyFactory;
    private final Cipher cipher;

    // Custom Exceptions
    class VaultReadFailedException extends Exception{}
    class DecryptionFailedException extends Exception{}
    class EncryptionFailedException extends Exception{}

    // RUN PROGRAM
    public static void main(String[] args) {
        try (PasswordManager p = new PasswordManager()) {
            p.runProgram();
        }
        // Handles unrecoverable exceptions that can be thrown during execution
        catch (AEADBadTagException _){
            System.out.println("Incorrect password");
        } catch(NoSuchAlgorithmException | NoSuchPaddingException _){
            System.out.println("Error: Unsupported version of java, use at least java 8? or later.");
        } catch (VaultReadFailedException _){
            System.out.println("Error: Unable to read from vault, try rerunning program.");
        } catch (DecryptionFailedException _) {
            System.out.println("Error: Decryption failed, try rerunning program.");
        } catch (EncryptionFailedException _) {
            System.out.println("Error: Re-encrypting passwords failed, any new passwords added will not be saved.");
            System.out.println("Try rerunning program and then readding the new in order to save them.");
        } catch (IOException _){
            System.out.println("Error: unable to read master password, try rerunning program.");
        }
    }

    // Initializes the password manager
    public PasswordManager() throws NoSuchAlgorithmException, NoSuchPaddingException, IOException{
        // Gets master password from user
        if (passwordVault.exists()) {
            System.out.println("Enter Master Password: ");
        } else{
            System.out.println("Creating new vault: Enter the password you want to use to access the vault: ");
        }
        masterPassword = getCharInput();
        System.out.print("\033[1F\033[2K"); // Erases previous line
        System.out.println("**********");

        // Initializes cryptography related classes that can error while initializing
        keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        cipher = Cipher.getInstance("AES/GCM/NoPadding");
    }

    // Runs the password manager
    private void runProgram()
            throws AEADBadTagException, VaultReadFailedException, DecryptionFailedException, EncryptionFailedException
    {
        // Decrypts vault and stores data in the passwords list
        decryptVault();

        // Runs the main program
        mainLoop();

        // Reencrypts password data
        encryptVault();
    }

    // Loop that lets user select what command they want to execute
    private void mainLoop(){
        System.out.println("\n\nType one of the following commands in order to proceed:\n");
        System.out.println("   view: displays the names of all password");
        System.out.println("   add: adds a new password");
        System.out.println("   get: retrieves one of the passwords");
        System.out.println("   master: changes the master password");
        System.out.println("   exit: exits the password manager");

        // Allows the user to enter commands
        while(true){
            System.out.println("\nEnter the command you want to execute");
            String input = getStringInput();
            try {
                switch (input) {
                    case "view":
                        view();
                        break;
                    case "add":
                        add();
                        break;
                    case "get":
                        break;
                    case "master":
                        break;
                    case "exit":
                        return;     // Returns if program is exited
                    default:
                        System.out.println("Unrecognized command");
                }
            }
            catch (IOException _){
                System.out.println("Error processing entered text");
            }
        }
    }

    // Closes all resources and clears any sensitive data
    public void close(){
        inputScanner.close();
        passwords.clear();
        Arrays.fill(masterPassword, '0');
    }

    // USER FUNCTIONALITY
    // Prints the names of all passwords currently stored in the password list
    private void view(){
        SafePasswordList.Node walker = passwords.getHead();
        if (walker != null) System.out.println();

        while(walker != null){
            System.out.println(walker.getName());
            walker = walker.getNext();
        }
    }
    // Adds a new password
    private void add() throws IOException{
        char[] name = null;
        char[] username;
        char[] password;

        // Makes sure name is not already in use
        boolean validName = false;
        while (!validName) {
            System.out.println("Enter a name that you can use to reference your password");
            name = getCharInput();

            // Checks if any prior passwords match with name
            SafePasswordList.Node walker = passwords.getHead();
            if (walker == null){
                validName = true;
            }
            while (walker != null) {
                if (Arrays.equals(name, walker.getName())){
                    System.out.println("That name is already taken");
                    break;
                }
                walker = walker.getNext();
                // If no prior names are equal
                if (walker == null){
                    validName = true;
                }
            }
        }
        System.out.println("Enter a username to associate with your password");
        username = getCharInput();

        System.out.println("Enter what you want your password to be");
        password = getCharInput();

        passwords.append(name, username, password);
    }

    // ENCRYPTION/ DECRYPTION
    // Decrypts the vault and reads it into passwords
    void decryptVault() throws AEADBadTagException, DecryptionFailedException, VaultReadFailedException{
        // Decrypts vault and stores data in the passwords list
        if (passwordVault.exists()){
            // Stores variables that will need to be overwritten during cleanup
            SecretKey temp = null;
            SecretKey masterKey = null;
            byte[] decryptedBytes = null;
            PBEKeySpec masterKeyPBESpec = null;

            try(final BufferedInputStream vaultInput = new BufferedInputStream(new FileInputStream(passwordVault))){
                // Creates lambda to get unencrypted numbers from the vault
                interface Function0{
                    int get() throws IOException;
                } Function0 getNumber = () -> {
                    byte[] numberBytes = new byte[Integer.BYTES];
                    int _ = vaultInput.read(numberBytes);
                    return bytesToInt(numberBytes);
                };

                // Gets decryption data from the vault
                int versionNumber = getNumber.get();    // Future proofing
                // Gets the salt from the vault
                int saltSize = getNumber.get();
                byte[] salt = new byte[saltSize];
                int _ = vaultInput.read(salt);
                // Gets the iv from the vault
                int ivSize = getNumber.get();
                byte[] iv = new byte[ivSize];
                int _ = vaultInput.read(iv);
                // Gets key generator iteration count and GMC tag size from the vault
                int keyGeneratorIterationCount = getNumber.get();
                int gmcTagSize = getNumber.get();

                // Creates the decryption key
                masterKeyPBESpec = new PBEKeySpec(masterPassword, salt, keyGeneratorIterationCount, MASTER_KEY_SIZE);
                temp = keyFactory.generateSecret(masterKeyPBESpec);
                masterKey = new SecretKeySpec(temp.getEncoded(), "AES");

                // Sets up the cipher used to encrypt data to the file
                GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(gmcTagSize, iv);
                cipher.init(Cipher.DECRYPT_MODE, masterKey, gcmParameterSpec);

                // Gets all encrypted bytes from the file
                int encryptedDataLength = (int)passwordVault.length() - (5*Integer.BYTES) - ivSize - saltSize;
                byte[] encryptedBytes = new byte[encryptedDataLength];
                int _ = vaultInput.read(encryptedBytes);

                // Decrypts bytes and stores them in the passwords linked list
                decryptedBytes = cipher.doFinal(encryptedBytes);
                for(int i = 0; i < decryptedBytes.length;){

                    // Gets name size
                    byte[] nameSizeBytes = new byte[Integer.BYTES];
                    for(int j = 0; j < Integer.BYTES; i++, j++){
                        nameSizeBytes[j] = decryptedBytes[i];
                    } int nameSize = bytesToInt(nameSizeBytes);
                    // Gets the name
                    byte[] nameBytes = new byte[nameSize];
                    for(int j = 0; j < nameSize; i++, j++){
                        nameBytes[j] = decryptedBytes[i];
                    } char[] name = bytesToChars(nameBytes);

                    // Gets username size
                    byte[] usernameSizeBytes = new byte[Integer.BYTES];
                    for(int j = 0; j < Integer.BYTES; i++, j++){
                        usernameSizeBytes[j] = decryptedBytes[i];
                    } int usernameSize = bytesToInt(usernameSizeBytes);
                    // Gets the username
                    byte[] usernameBytes = new byte[usernameSize];
                    for(int j = 0; j < usernameSize; i++, j++){
                        usernameBytes[j] = decryptedBytes[i];
                    } char[] username = bytesToChars(usernameBytes);

                    // Gets password size
                    byte[] passwordSizeBytes = new byte[Integer.BYTES];
                    for(int j = 0; j < Integer.BYTES; i++, j++){
                        passwordSizeBytes[j] = decryptedBytes[i];
                    } int passwordSize = bytesToInt(passwordSizeBytes);
                    // Gets the password
                    byte[] passwordBytes = new byte[passwordSize];
                    for(int j = 0; j < passwordSize; i++, j++){
                        passwordBytes[j] = decryptedBytes[i];
                    } char[] password = bytesToChars(passwordBytes);

                    // Adds data to the list
                    passwords.append(name, username, password);
                }
            }
            // Incorrect password entered
            catch (AEADBadTagException e){
                throw e;
            }
            // Reading from file failed
            catch(IOException _){
                throw new VaultReadFailedException();
            }
            // Error initializing decryption related classes
            catch (Exception _){
                throw new DecryptionFailedException();
            }
            // Overwrites sensitive data
            finally {
                // Attempts to clear master password data stored in keys
                if (masterKeyPBESpec != null) masterKeyPBESpec.clearPassword();
                try {
                    if (temp != null) temp.destroy();
                    if (masterKey != null) masterKey.destroy();
                } catch (DestroyFailedException _){}
                // Overwrites the decrypted bytes array
                if (decryptedBytes != null) Arrays.fill(decryptedBytes, (byte)0);
            }
        }
    }

    // Reencrypts the passwords
    void encryptVault() throws EncryptionFailedException{
        // Stores variables that will need to be cleaned up later
        PBEKeySpec masterKeyPBESpec = null;
        SecretKey temp = null;
        SecretKey masterKey = null;

        // Creates iv and salt
        byte[] salt = new byte[SALT_SIZE];
        byte[] iv = new byte[IV_SIZE];
        random.nextBytes(salt);
        random.nextBytes(iv);

        // Creates a file to hold reencrypted data
        try {
            if (tempPasswordVault.exists()){
                boolean _ = tempPasswordVault.delete();
            }
            boolean _ = tempPasswordVault.createNewFile();
        }
        catch(IOException _){
            throw new EncryptionFailedException();
        }

        // Sends encrypted data to the file
        try(FileOutputStream outputVault = new FileOutputStream(tempPasswordVault)){
            // Writes salt, iv, keyGenIterationCount, and gcmTagSize to the start of the vault
            outputVault.write(intToBytes(VERSION_NUMBER));
            outputVault.write(intToBytes(SALT_SIZE));
            outputVault.write(salt);
            outputVault.write(intToBytes(IV_SIZE));
            outputVault.write(iv);
            outputVault.write(intToBytes(KEY_GENERATOR_ITERATION_COUNT));
            outputVault.write(intToBytes(GCM_TAG_SIZE));

            // Creates the encryption key
            masterKeyPBESpec = new PBEKeySpec(masterPassword, salt, KEY_GENERATOR_ITERATION_COUNT, MASTER_KEY_SIZE);
            temp = keyFactory.generateSecret(masterKeyPBESpec);
            masterKey = new SecretKeySpec(temp.getEncoded(), "AES");

            // Sets up the stream used to encrypt data to the file
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_SIZE, iv);
            cipher.init(Cipher.ENCRYPT_MODE, masterKey, gcmParameterSpec);
            try (BufferedOutputStream encryptedOutput = new BufferedOutputStream(new CipherOutputStream(outputVault, cipher))){

                // Encrypts all data in the password list to the file
                // Formated as <int(Big Endian)><bytes(UTF-8 encoding)>
                SafePasswordList.Node walker = passwords.getHead();
                while (walker != null){

                    // Writes the name to the vault
                    byte[] nameBytes = charsToBytes(walker.getName());
                    int nameByteLen = nameBytes.length;
                    encryptedOutput.write(intToBytes(nameByteLen));
                    encryptedOutput.write(nameBytes);

                    // Writes the username to the vault
                    byte[] usernameBytes = charsToBytes(walker.getUsername());
                    int usernameByteLen = usernameBytes.length;
                    encryptedOutput.write(intToBytes(usernameByteLen));
                    encryptedOutput.write(usernameBytes);

                    // Writes the password to the vault
                    byte[] passwordBytes = charsToBytes(walker.getPassword());
                    int passwordByteLen = passwordBytes.length;
                    encryptedOutput.write(intToBytes(passwordByteLen));
                    encryptedOutput.write(passwordBytes);

                    // Increments to next password
                    walker = walker.getNext();
                }
            }
            // Replaces old vault file with the newly created one
            boolean _ = passwordVault.delete();
            boolean _ = tempPasswordVault.renameTo(passwordVault);
        }
        catch(Exception _) {
            boolean _ = tempPasswordVault.delete();
            throw new EncryptionFailedException();
        }
        finally {
            // Attempts to clear master password data stored in keys
            if (masterKeyPBESpec != null) masterKeyPBESpec.clearPassword();
            try {
                if (temp != null) temp.destroy();
                if (masterKey != null) masterKey.destroy();
            } catch (DestroyFailedException _){}
        }
    }

    // HELPER FUNCTIONS
    // Gets a single word from user input and clears the remaining buffer
    private String getStringInput(){
        String input = inputScanner.next();
        // Discards remaining input
        inputScanner.nextLine();
        return input;
    }
    // Converts a char array to a UTF_8 byte array
    private byte[] charsToBytes(char[] chars){
        CharBuffer charB = CharBuffer.wrap(chars);
        ByteBuffer byteB = StandardCharsets.UTF_8.encode(charB);
        return  byteB.array();
    }
    // Converts a UTF_8 byte array to a char array
    private char[] bytesToChars(byte[] bytes){
        ByteBuffer byteB = ByteBuffer.wrap(bytes);
        CharBuffer charB = StandardCharsets.UTF_8.decode(byteB);
        return charB.array();
    }
    private byte[] intToBytes(int num){
        ByteBuffer byteB = ByteBuffer.allocate(Integer.BYTES);
        byteB.order(ByteOrder.BIG_ENDIAN);
        byteB.putInt(num);
        return byteB.array();
    }
    private int bytesToInt(byte[] bytes){
        ByteBuffer byteB = ByteBuffer.allocate(Integer.BYTES);
        byteB.order(ByteOrder.BIG_ENDIAN);
        byteB.put(bytes);
        return byteB.getInt(0);
    }

    // Gets a line from user input and stores it as a char array, then clears any remaining buffer
    // Also trims any leading or trailing whitespace
    private char[] getCharInput() throws IOException{
        char[] inputtedChars;
        SafeCharList charList = new SafeCharList();

        // Reads from the input char by char
        try{
            // Variables to detect newline
            char[] lineSeparator = System.lineSeparator().toCharArray();
            boolean twoCharLineSeparator = lineSeparator.length == 2;

            // Loops until user enters valid input
            while (charList.isEmpty()){
                // Reads in initial characters
                int current = inputCharReader.read();
                // Checks if eos reached
                if (current != -1) {
                    char currentChar = (char)current;
                    // Checks if current char is valid
                    if ( currentChar != ' '
                            && currentChar != lineSeparator[0]
                            && (!twoCharLineSeparator || currentChar != lineSeparator[1])
                            && current >= 32 && current != 127){ // Discard standard nonprintable characters
                        charList.append(currentChar);
                    }
                }
            }
            // Gets the rest of the text inputted by the user
            boolean endReached = false;
            while (!endReached){
                // Reads the current char
                int current = inputCharReader.read();
                // Checks if eos reached
                if (current != -1) {
                    char currentChar = (char)current;
                    // First char of line separator reached
                    if (lineSeparator[0] == currentChar){
                        endReached = true;
                    }
                    // Other common line separator reached
                    // (useful when running in emulators that don't use system line separator)
                    else if (currentChar == '\n' || currentChar == '\r'){
                        endReached = true;
                    }
                    // Stores valid input (skips non printable chars)
                    else if(current >= 32 && current != 127){
                        charList.append(currentChar);
                    }
                }
            }
            // Discards any remaining text
            while (inputCharReader.ready())
                inputCharReader.readLine();
            charList.trimTrailingWhitespace();
            inputtedChars = charList.toCharArray();
        }
        finally {
            charList.clear();
        }
        return inputtedChars;
    }
}