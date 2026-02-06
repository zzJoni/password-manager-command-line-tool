import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Scanner;

public class PasswordManager {
    // Initialize necessary classes
    private static final SecureRandom random = new SecureRandom();
    private final BufferedReader inputCharReader = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
    private final Scanner inputScanner = new Scanner(System.in, StandardCharsets.UTF_8);
    private final File passwordVault = new File("password_vault.enc");
    private final File tempPasswordVault = new File("temp_password_vault.enc");

    // Stores passwords until they get reencrypted
    private final SafePasswordList passwords = new SafePasswordList();

    // Stores data necessary for creating master key
    private static final int VERSION_NUMBER = 1; // Stores the version of the vault file
    private static final int SALT_SIZE = 16;
    private static final int IV_SIZE = 12;
    private static final int GCM_TAG_SIZE = 16*8; // 128 bits
    private static final int MASTER_KEY_SIZE = 32*8; // 256 bits
    private static final int KEY_GENERATOR_ITERATION_COUNT = 600_000;
    private char[] masterPassword;

    // Stores cryptography related classes
    private SecretKeyFactory keyFactory;
    private Cipher cipher;

    // PROGRAM START POINT
    public static void main(String[] args){
        PasswordManager p = new PasswordManager();
        p.init();
    }

    // Sets up the password manager
    private void init(){
        // Gets master password from user
        boolean vaultExists = passwordVault.exists();
        if (vaultExists) {
            System.out.println("Enter Master Password: ");
        } else{
            System.out.println("Creating new vault: Enter the password you want to use to access the vault: ");
        }
        masterPassword = getCharInput();
        System.out.print("\033[1F\033[2K"); // Erases previous line
        System.out.println("**********");

        // Initializes cryptography related classes that can error while initializing
        try{
            keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            cipher = Cipher.getInstance("AES/GCM/NoPadding");
        }catch(Exception _){
            System.out.println("Error: Unsupported version of java");
        }

        // Decrypts vault and stores data in the passwords list
        if (vaultExists){
            try(BufferedInputStream vaultInput = new BufferedInputStream(new FileInputStream(passwordVault))){
                // Gets version number from the vault
                byte[] versionNumBytes = new byte[Integer.BYTES];
                int _ = vaultInput.read(versionNumBytes);
                int versionNumber = bytesToInt(versionNumBytes);
                System.out.println("Version: " + versionNumber);  // Debug

                // Gets the salt from the vault
                byte[] saltSizeBytes = new byte[Integer.BYTES];
                int _ = vaultInput.read(saltSizeBytes);
                int saltSize = bytesToInt(saltSizeBytes);
                byte[] salt = new byte[saltSize];
                int _ = vaultInput.read(salt);

                // Gets the iv from the vault
                byte[] ivSizeBytes = new byte[Integer.BYTES];
                int _ = vaultInput.read(ivSizeBytes);
                int ivSize = bytesToInt(ivSizeBytes);
                byte[] iv = new byte[ivSize];
                int _ = vaultInput.read(iv);

                // Gets key generator iteration count from the vault
                byte[] iterationCountBytes = new byte[Integer.BYTES];
                int _ = vaultInput.read(iterationCountBytes);
                int keyGeneratorIterationCount = bytesToInt(iterationCountBytes);
                System.out.println("Key gen iteration count: " + keyGeneratorIterationCount);  // Debug

                // Gets GCM tag size from the vault
                byte[] gmcTagSizeBytes = new byte[Integer.BYTES];
                int _ = vaultInput.read(gmcTagSizeBytes);
                int gmcTagSize = bytesToInt(gmcTagSizeBytes);
                System.out.println("GCM tag size: " + gmcTagSize);  // Debug

                // Creates the decryption key
                PBEKeySpec masterKeyPBESpec = new PBEKeySpec(masterPassword, salt, keyGeneratorIterationCount, MASTER_KEY_SIZE);
                SecretKey temp = keyFactory.generateSecret(masterKeyPBESpec);
                SecretKey masterKey = new SecretKeySpec(temp.getEncoded(), "AES");

                // Sets up the cipher used to encrypt data to the file
                GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(gmcTagSize, iv);
                cipher.init(Cipher.DECRYPT_MODE, masterKey, gcmParameterSpec);

                // Gets all encrypted bytes from the file
                int encryptedDataLength = (int)passwordVault.length() - (5*Integer.BYTES) - ivSize - saltSize;
                byte[] encryptedBytes = new byte[encryptedDataLength];
                int _ = vaultInput.read(encryptedBytes);

                // Decrypts bytes and stores them in the passwords linked list
                byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
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
                    for(int j = 0; j < nameSize; i++, j++){
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
            catch(AEADBadTagException _){
                System.out.println("Incorrect master key");
            }
            catch(Exception e){
                System.out.println("Error: Unable to read from vault file");
            }
        }

        // Runs the main program
        try {
            mainLoop();
        }
        catch(Exception _){
            System.out.println("Error: Idk, I haven't implemented this lol");
        }
        // Reencrypts password data
        finally {
            byte[] salt = new byte[SALT_SIZE];
            byte[] iv = new byte[IV_SIZE];
            random.nextBytes(salt);
            random.nextBytes(iv);

            // Creates a file to hold reencrypted data
            try {
                boolean _ = tempPasswordVault.createNewFile();
            }
            catch(Exception _){ // TODO: Make this propagate up call stack
                System.out.println("Error: Creation of output vault file failed");
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
                PBEKeySpec masterKeyPBESpec = new PBEKeySpec(masterPassword, salt, KEY_GENERATOR_ITERATION_COUNT, MASTER_KEY_SIZE);
                SecretKey temp = keyFactory.generateSecret(masterKeyPBESpec);
                SecretKey masterKey = new SecretKeySpec(temp.getEncoded(), "AES");

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
            catch(IOException _){
                System.out.println("Error: Error writing to vault file");
                boolean _ = tempPasswordVault.delete();
            }
            catch(Exception e){
                System.out.println("Error: Error creating master key");
                boolean _ = tempPasswordVault.delete();
            }
            // Does cleanup
            finally {
                inputScanner.close();
                passwords.clear();
                Arrays.fill(masterPassword, '0');
            }
        }
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

            switch (input){
                case "view": view();
                    break;
                case "add": add();
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
    }
    // TERMINAL COMMANDS
    // Prints the names of all passwords currently stored in the password list
    private void view(){
        SafePasswordList.Node walker = passwords.getHead();
        while(walker != null){
            System.out.println(walker.getName());
            walker = walker.getNext();
        }
    }
    // Adds a new password
    private void add(){
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
    private char[] getCharInput(){
        char[] inputtedChars = null;
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
            // Discards and remaining text
            while (inputCharReader.ready())
                inputCharReader.readLine();
            charList.trimTrailingWhitespace();
            inputtedChars = charList.toCharArray();
        }
        catch (Exception _){
            System.out.println("Error: Unable to read input");
        }
        finally {
            charList.clear();
        }
        return inputtedChars;
    }
}