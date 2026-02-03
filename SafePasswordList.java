import java.io.Closeable;

// This helper class is a linked list that holds decrypted data that it
// automatically overwrites upon close
class SafePasswordList implements Closeable {
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