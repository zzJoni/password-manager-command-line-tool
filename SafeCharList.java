import java.io.Closeable;

// This helper class is a linked list that holds chars that it
// automatically overwrites upon close
class SafeCharList implements Closeable {
    static class Node{
        Node(char data){this.data = data;}
        char data;
        Node next;

        char getData(){return data;}
        void clearData(){data = 0;}
        Node getNext(){return next;}
    }
    private Node head;
    private Node tail;
    private int length;

    // Getters
    Node getHead(){return head;}
    Node getTail(){return tail;}

    // Adds a node to the start of the list
    void add(char data){
        Node temp = new Node(data);
        if (head ==  null){
            head = temp;
            tail = temp;
        } else{
            temp.next = head;
            head = temp;
        }
        length++;
    }
    // Adds a node to the end of the list
    void append(char data){
        Node temp = new Node(data);
        if (head ==  null){
            head = temp;
            tail = temp;
        } else{
            tail.next = temp;
            tail = temp;
        }
        length++;
    }
    // Returns a char array constructed using the chars in the list
    char[] getCharArray(){
        Node walker = head;
        char[] chars = new char[length];
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
    }
}