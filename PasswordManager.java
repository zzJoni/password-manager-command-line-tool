// File editing
import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;

public class PasswordManager {
    // Initialize necessary classes
    private final BufferedReader inputCharReader = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
    private final Scanner inputScanner = new Scanner(System.in, StandardCharsets.UTF_8);
    private final File passwordVault = new File("password_vault.txt");

    // Stores passwords until they get reencrypted
    private final SafePasswordList passwords = new SafePasswordList();
    private String masterPassword;

    // Compared to first line in file to test if decryption is successful
    private final String testDecryption = "Decrypted";

    // PROGRAM START POINT
    public static void main(String[] args){
        PasswordManager p = new PasswordManager(); //TODO: Make this a try with resources
        p.init();
    }

    // Sets up the password manager
    private void init(){
        // Attempts to create the password vault file if it was not created already
        boolean newVaultCreated = false;
        try {
            newVaultCreated = passwordVault.createNewFile();
        }
        catch(Exception _){
            System.out.println("Error: Creation of vault file failed");
        }

        System.out.println("Enter Master Password: ");
        masterPassword = getStringInput();
        System.out.print("\033[1F\033[2K"); // Erases previous line
        System.out.println("**********");
        mainLoop();

        //TODO: Move into close() function
        inputScanner.close();
        passwords.close();
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
    }
    // TERMINAL COMMANDS
    // Prints the names of all passwords currently stored in the password list
    private void view(){
        SafePasswordList.Node walker = passwords.getHead();
        while(walker != null){
            printCharArrayLn(walker.getName());
            walker = walker.getNext();
        }
    }
    // Adds a new password (unfinished)
    private void add(){
        System.out.println(getCharInput());
    }


    // HELPER FUNCTIONS
    // Gets a string from user input and clears the remaining buffer
    private String getStringInput(){
        String input = inputScanner.next();
        inputScanner.nextLine();
        return input;
    }

    // Gets a char array from user input and clears the remaining buffer
    private char[] getCharInput(){
        char[] inputtedChars = null;

        // Reads from the input char by char
        try(SafeCharList charList = new SafeCharList()){

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
                    if (currentChar != ' '
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
                    // Deliminator reached
                    if (currentChar == ' '){
                        endReached = true;
                    }
                    // Line separator reached for single char line separator
                    else if (!twoCharLineSeparator && lineSeparator[0] == currentChar){
                        endReached = true;
                    }
                    // Line separator reached for two char line separator
                    else if (twoCharLineSeparator && (lineSeparator[0] == currentChar || lineSeparator[1] == currentChar)){
                        endReached = true;
                    }
                    // Stores valid input (skips non printable chars)
                    else if(current >= 32 && current != 127){
                        charList.append(currentChar);
                    }
                }
            }
            // Discards and remaining text
            if (inputCharReader.ready())
                inputCharReader.readLine();
            inputtedChars = charList.toCharArray();
        }
        catch (Exception _){
            System.out.println("Error: Unable to read input");
        }
        return inputtedChars;
    }

    // Prints a char array to terminal (does not append newline)
    private void printCharArray(char[] chars){
        for(char c : chars){
            System.out.print(c);
        }
    }
    private void printCharArrayLn(char[] chars){
        printCharArray(chars);
        System.out.println();
    }
}