// File editing
import java.io.File;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;

public class PasswordManager {
    // Initialize necessary classes
    private final Scanner inputScanner = new Scanner(System.in, StandardCharsets.UTF_8);
    private final File passwordVault = new File("password_vault.txt");
    private final InputStreamReader inputCharReader = new InputStreamReader(System.in, StandardCharsets.UTF_8);

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
    // Adds a new password
    private void add(){
        System.out.println(getCharInput());
    }


    // HELPER FUNCTIONS
    // Gets a string from the inputChar and clears the remaining buffer
    private String getStringInput(){
        String input = inputScanner.next();
        inputScanner.nextLine();
        return input;
    }

    // Gets a char array from the inputChar and clears the remaining buffer
    private char[] getCharInput(){
        char[] inputtedChars = null;

        // Reads from the input char by char
        try(SafeCharList charList = new SafeCharList()){

            // Variables to detect newline
            char[] lineSeparator = System.lineSeparator().toCharArray();
            boolean twoCharLineSeparator = lineSeparator.length == 2;
            SafeCharList.Node prior = null;

            // Stores whether any usable input has been entered
            boolean validInput = false;

            // Loops until user enters valid input
            while (!validInput){
                // Reads in initial characters
                int current = inputCharReader.read();
                // Checks if eos reached
                if (current != -1) {
                    char currentChar = (char)current;
                    // Checks if current char is not deliminator
                    if (currentChar != ' '){
                        // Resets input storage if first 2 characters are 2 char line separator
                        if (twoCharLineSeparator
                                && prior != null
                                && prior.getData() == lineSeparator[0]
                                && currentChar == lineSeparator[1]) {
                            charList.close(); // Resets list back to empty state
                            prior = null;
                        }
                        // Sets input to be valid if both chars are good
                        else if (twoCharLineSeparator && prior != null){
                            charList.append(currentChar);
                            prior = prior.getNext();
                            validInput = true;
                        }
                        // Appends value if it is the first and line separator is 2 chars
                        else if (twoCharLineSeparator){
                            charList.append(currentChar);
                            prior = charList.getHead();
                        }
                        // Sets input to be valid if 1 char line separator and valid input
                        else if (currentChar != lineSeparator[0]){
                            charList.append(currentChar);
                            prior = charList.getHead();
                            validInput = true;
                        }
                    }
                }
            }



            inputtedChars = charList.toCharArray();
        }
        catch (Exception _){}

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