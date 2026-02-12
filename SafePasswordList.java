import java.io.Closeable;
import java.util.Arrays;

// This helper class is a linked list that holds decrypted data that it
// automatically overwrites upon close
class SafePasswordList {
    static class Node{
        Node(char[] name, char[] username, char[] password){
            this.name = name;
            this.username = username;
            this.password = password;
        }
        private char[] name;
        private char[] username;
        private char[] password;
        private Node next;

        // Getters
        char[] getName(){return name;}
        char[] getUsername(){return username;}
        char[] getPassword(){return password;}
        Node getNext(){return next;}

        // Setters
        void setName(char[] name){
            Arrays.fill(this.name, '0');
            this.name = name;
        }
        void setUsername(char[] username){
            Arrays.fill(this.username, '0');
            this.username = username;
        }
        void setPassword(char[] password){
            Arrays.fill(this.password, '0');
            this.password = password;
        }
    }
    private Node head;
    private Node tail;

    // Getters
    Node getHead(){return head;}
    Node getTail(){return tail;}

    boolean isEmpty(){return head == null;}

    // Adds a node to the start of the list
    void add(char[] name, char[] username, char[] password){
        Node temp = new Node(name, username, password);
        if (head ==  null){
            tail = temp;
        } else{
            temp.next = head;
        }
        head = temp;
    }
    // Adds a node to the end of the list
    void append(char[] name, char[] username, char[] password){
        Node temp = new Node(name, username, password);
        if (head ==  null){
            head = temp;
        } else{
            tail.next = temp;
        }
        tail = temp;
    }
    // Overwrites data so it does not remain in memory
    public void clear(){
        while (head != null){
            Arrays.fill(head.getName(), '0');
            Arrays.fill(head.getUsername(), '0');
            Arrays.fill(head.getPassword(), '0');
            head = head.getNext();
        }
        tail = null;
    }
}