import java.io.File;
import java.io.Writer;
import java.io.BufferedWriter;
import java.io.OutputStreamWriter;
import java.io.FileOutputStream;
import java.io.Closeable;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;

// This helper class is a linked list that holds decrypted data that it
// automatically overwrites upon close
class SafeLinkedList implements Closeable{
    static class Node{
        Node(char[] data){this.data = data;}
        char[] data;
        Node next;

        char[] getData(){return data;}
        Node getNext(){return next;}
    }
    private Node head;
    private Node tail;

    // Getters
    Node getHead(){return head;}
    Node getTail(){return tail;}

    // Adds a node to the start of the list
    void add(char[] data){
        Node temp = new Node(data);
        if (head ==  null){
            head = temp;
            tail = temp;
        } else{
            temp.next = head;
            head = temp;
        }
    }
    // Adds a node to the end of the list
    void append(char[] data){
        Node temp = new Node(data);
        if (head ==  null){
            head = temp;
            tail = temp;
        } else{
            tail.next = temp;
            tail = temp;
        }
    }
    // Overwrites data so it does not remain in memory
    public void close(){
        while (head != null){
            for (char c : head.getData()){
                c = 0;
            }
            head = head.getNext();
        }
        tail = null;
    }
}

public class PasswordManager {
    // Initialize necessary classes
    private final Scanner inputScanner = new Scanner(System.in, StandardCharsets.UTF_8);
    File passwordVault = new File("password_vault.txt");

    // Stores master password until file gets encrypted
    private String masterPassword;

    // Compared to first line in file to test if decryption is successful
    private String testDecryption = "Decrypted";

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

        // Makes first line of vault a known value in order to help test if vault has been decrypted
        if (newVaultCreated){
            try {
                Writer writer = new BufferedWriter(new OutputStreamWriter(
                        new FileOutputStream("password_vault.txt"), StandardCharsets.UTF_8));
                writer.write(testDecryption);
                writer.close();
            }
            catch (Exception _){
                System.out.println("Error: Unable to write to vault file");
            }
        }

        System.out.println("Enter Master Password: ");
        masterPassword = getStringInput();
        System.out.println(masterPassword);
        mainLoop();

        inputScanner.close();
    }

    // Loop that lets user select what command they want to execute
    private void mainLoop(){
        System.out.println("\n\nType one of the following commands in order to proceed:\n");
        System.out.println("   view: displays the names of all password");
        System.out.println("   add: adds a new password");
        System.out.println("   get: retrieves one of the passwords");
        System.out.println("   exit: exits the password manager");

        // Allows the user to enter commands
        while(true){
            System.out.println("\nEnter the command you want to execute");
            String input = getStringInput();

            switch (input){
                case "view":
                    break;
                case "add":
                    break;
                case "get":
                    break;
                case "exit":
                    return;     // Returns if program is exited
                default:
                    System.out.println("Unrecognized command");
            }
        }
    }

    private void view(){
        try(Scanner reader = new Scanner(passwordVault);) {

        }
        catch (Exception _){
            System.out.println("Error: unable to read vault file");
        }
    }

    // Gets a string from the input and clears the remaining buffer
    private String getStringInput(){
        String input = inputScanner.next();
        inputScanner.nextLine();
        return input;
    }
}