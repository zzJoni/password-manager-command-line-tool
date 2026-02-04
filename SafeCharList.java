import java.io.Closeable;

// This helper class is a linked list that holds chars that it
// automatically overwrites upon close
class SafeCharList implements Closeable {
    static class Node{
        Node(char data){this.data = data;}
        private char data;
        private Node next;
        private Node prev;

        char getData(){return data;}
        void clearData(){data = 0;}
        Node getNext(){return next;}
    }
    private Node head;
    private Node tail;
    private int size = 0;

    // Getters
    Node getHead(){return head;}
    Node getTail(){return tail;}

    boolean isEmpty(){return head == null;}

    // Adds a node to the start of the list
    void add(char data){
        Node temp = new Node(data);
        if (head ==  null){
            head = temp;
            tail = temp;
        } else{
            temp.next = head;
            head.prev = temp;
            head = temp;
        }
        size++;
    }
    // Adds a node to the end of the list
    void append(char data){
        Node temp = new Node(data);
        if (head ==  null){
            tail = temp;
            head = temp;
        } else{
            tail.next = temp;
            temp.prev = tail;
            tail = temp;
        }
        size++;
    }
    // Trims trailing whitespace
    void trimTrailingWhitespace(){
        while (tail.getData() == ' '){
            tail.clearData();
            tail = tail.prev;
            tail.next = null;
        }
    }

    // Returns a char array constructed using the chars in the list
    char[] toCharArray(){
        Node walker = head;
        char[] chars = new char[size];
        int count = 0;
        while (walker != null){
            chars[count] = walker.getData();
            count++;
            walker = walker.getNext();
        }
        return chars;
    }

    // Overwrites data so it does not remain in memory
    public void close(){
        while (head != null){
            head.clearData();
            head = head.getNext();
        }
        tail = null;
        size = 0;
    }
}